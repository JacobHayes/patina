//! signal/eintr — the kernel's per-call restart rule (man 7 signal,
//! "Interruption of system calls and library functions by signal handlers"):
//! a blocking `read` without `SA_RESTART` fails `EINTR`, with `SA_RESTART` it
//! is restarted and completes on the later write; `nanosleep` and a relative
//! `clock_nanosleep` are never restarted and fill `remain` inside
//! `(0, request]` (an absolute `clock_nanosleep` leaves `remain` untouched);
//! `epoll_wait` is never restarted; a `FUTEX_WAIT` without a timeout is
//! restarted under `SA_RESTART` (`ERESTARTSYS`) and `EINTR` without it, and
//! one with a timeout is `EINTR` regardless (`ERESTART_RESTARTBLOCK` under a
//! handler). Every helper marks the stream before it kills, so a wait that
//! returned early is visible as an ordering divergence.

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use serde_json::Value;
    use std::sync::atomic::AtomicU32;
    use std::thread;
    use syscall_conformance::calls::{neg, Probe};

    const WAIT: i32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
    const WAKE: i32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

    fn delayed_kill<'a>(scope: &'a thread::Scope<'a, '_>, p: &'a Probe, pid: pid_t, sig: c_int) {
        let main_tid = support::gettid();
        scope.spawn(move || {
            support::until_parked(main_tid);
            p.mark("helper_kill", &[("sig", Value::from(sig))]);
            unsafe {
                kill(pid, sig);
            }
        });
    }

    pub fn run(p: &Probe) {
        support::reset();
        let pid = p.getpid() as pid_t;
        let main_tid = support::gettid();
        support::install(SIGUSR1, 0, false);
        let (r, fds) = p.pipe2(0);
        p.require("pipe", r == 0);
        let [rd, wr] = fds;
        thread::scope(|scope| {
            delayed_kill(scope, p, pid, SIGUSR1);
            p.check(
                "blocking read without SA_RESTART is EINTR",
                p.read(rd, 1).0 == neg(EINTR),
            );
        });
        p.check(
            "the handler ran once before read returned",
            support::count() == 1,
        );

        support::install(SIGUSR1, SA_RESTART, false);
        thread::scope(|scope| {
            scope.spawn(|| {
                support::until_parked(main_tid);
                p.mark("helper_kill", &[("sig", Value::from(SIGUSR1))]);
                unsafe {
                    kill(pid, SIGUSR1);
                }
                support::until_parked(main_tid);
                p.mark("helper_write", &[]);
                unsafe {
                    write(wr, b"x".as_ptr() as *const _, 1);
                }
            });
            let (n, data) = p.read(rd, 1);
            p.check(
                "blocking read with SA_RESTART resumes and completes on the later write",
                n == 1 && data == b"x",
            );
        });
        p.check(
            "the handler ran during the restarted read",
            support::count() == 2,
        );

        thread::scope(|scope| {
            delayed_kill(scope, p, pid, SIGUSR1);
            let (r, _) = p.nanosleep_rem(1, 0);
            p.check("nanosleep is never restarted", r == neg(EINTR));
        });
        thread::scope(|scope| {
            delayed_kill(scope, p, pid, SIGUSR1);
            let (r, _) = p.clock_nanosleep_rem(CLOCK_MONOTONIC, 0, 1, 0);
            p.check(
                "a relative clock_nanosleep is never restarted",
                r == neg(EINTR),
            );
        });
        let (_, now) = p.clock_gettime(CLOCK_MONOTONIC);
        let deadline = now + 1_000_000_000;
        thread::scope(|scope| {
            delayed_kill(scope, p, pid, SIGUSR1);
            let (r, _) = p.clock_nanosleep_rem(
                CLOCK_MONOTONIC,
                TIMER_ABSTIME,
                (deadline / 1_000_000_000) as i64,
                (deadline % 1_000_000_000) as i64,
            );
            p.check(
                "an absolute clock_nanosleep is never restarted",
                r == neg(EINTR),
            );
        });
        p.check("every sleep ran the handler once", support::count() == 5);

        let epfd = p.epoll_create1(0);
        p.require("epoll_create1", epfd >= 0);
        p.check(
            "watch the pipe's read end",
            p.epoll_ctl(epfd, EPOLL_CTL_ADD, rd, EPOLLIN as u32, 7) == 0,
        );
        thread::scope(|scope| {
            delayed_kill(scope, p, pid, SIGUSR1);
            let (n, _) = p.epoll_wait(epfd, 4, -1);
            p.check(
                "epoll_wait is never restarted, even under SA_RESTART",
                n == neg(EINTR),
            );
        });

        let word = AtomicU32::new(0);
        thread::scope(|scope| {
            scope.spawn(|| {
                support::until_parked(main_tid);
                p.mark("helper_kill", &[("sig", Value::from(SIGUSR1))]);
                unsafe {
                    kill(pid, SIGUSR1);
                }
                support::until_parked(main_tid);
                p.mark("helper_wake", &[]);
                p.rec.quiet(|| p.futex(&word, WAKE, 1, None));
            });
            p.check(
                "FUTEX_WAIT without a timeout restarts under SA_RESTART and returns on the wake",
                p.futex(&word, WAIT, 0, None) == 0,
            );
        });
        thread::scope(|scope| {
            delayed_kill(scope, p, pid, SIGUSR1);
            p.check(
                "FUTEX_WAIT with a timeout is EINTR even under SA_RESTART",
                p.futex(&word, WAIT, 0, Some(2_000_000_000)) == neg(EINTR),
            );
        });
        support::install(SIGUSR1, 0, false);
        thread::scope(|scope| {
            delayed_kill(scope, p, pid, SIGUSR1);
            p.check(
                "FUTEX_WAIT without SA_RESTART is EINTR",
                p.futex(&word, WAIT, 0, None) == neg(EINTR),
            );
        });
        p.check(
            "every interrupted call ran the handler exactly once",
            support::count() == 9,
        );
        p.close(epfd);
        p.close(rd);
        p.close(wr);
    }
}

syscall_conformance::probe_main!("signal/eintr", scenario::run);
