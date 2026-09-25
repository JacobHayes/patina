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
//! returned early is visible as an ordering difference.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE, Probe, neg};
use libc::*;
use std::sync::atomic::AtomicU32;
use std::thread;

pub fn run(p: &Probe) {
    support::reset();
    let pid = p.getpid() as pid_t;
    let main_tid = support::gettid();
    support::install(SIGUSR1, 0, false);
    let (r, fds) = p.pipe2(0);
    p.require("pipe", r == 0);
    let [rd, wr] = fds;
    thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
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
            support::kill_when_parked(p, main_tid, pid, SIGUSR1);
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
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        let (r, _) = p.nanosleep_rem(1, 0);
        p.check("nanosleep is never restarted", r == neg(EINTR));
    });
    thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        let (r, _) = p.clock_nanosleep_rem(CLOCK_MONOTONIC, 0, 1, 0);
        p.check(
            "a relative clock_nanosleep is never restarted",
            r == neg(EINTR),
        );
    });
    let (_, now) = p.clock_gettime(CLOCK_MONOTONIC);
    let deadline = now + 1_000_000_000;
    thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
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
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        let (n, _) = p.epoll_wait(epfd, 4, -1);
        p.check(
            "epoll_wait is never restarted, even under SA_RESTART",
            n == neg(EINTR),
        );
    });

    let word = AtomicU32::new(0);
    thread::scope(|scope| {
        scope.spawn(|| {
            support::kill_when_parked(p, main_tid, pid, SIGUSR1);
            support::until_parked(main_tid);
            p.mark("helper_wake", &[]);
            p.rec.quiet(|| p.futex(&word, FUTEX_WAKE_PRIVATE, 1, None));
        });
        p.check(
            "FUTEX_WAIT without a timeout restarts under SA_RESTART and returns on the wake",
            p.futex(&word, FUTEX_WAIT_PRIVATE, 0, None) == 0,
        );
    });
    thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.check(
            "FUTEX_WAIT with a timeout is EINTR even under SA_RESTART",
            p.futex(&word, FUTEX_WAIT_PRIVATE, 0, Some(2_000_000_000)) == neg(EINTR),
        );
    });
    support::install(SIGUSR1, 0, false);
    thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.check(
            "FUTEX_WAIT without SA_RESTART is EINTR",
            p.futex(&word, FUTEX_WAIT_PRIVATE, 0, None) == neg(EINTR),
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

pub const SCENARIO: Scenario = Scenario {
    name: "signal/eintr",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_pipe2,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_kill,
        Syscall::N_nanosleep,
        Syscall::N_clock_nanosleep,
        Syscall::N_clock_gettime,
        Syscall::N_epoll_create1,
        Syscall::N_epoll_ctl,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_epoll_wait,
        Syscall::N_futex,
    ],
    symbols: &[
        "getpid",
        "pipe2",
        "read",
        "write",
        "close",
        "kill",
        "nanosleep",
        "clock_nanosleep",
        "clock_gettime",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "syscall",
        "sigaction",
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
