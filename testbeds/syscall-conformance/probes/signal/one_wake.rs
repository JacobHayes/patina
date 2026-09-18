//! signal/one_wake — a process-directed signal interrupts exactly ONE thread:
//! the thread group leader when it does not block the signal, else a thread
//! that does not (kernel/signal.c complete_signal: `wants_signal(sig, p)` for
//! the task the pid names — the leader — then the other threads). A thread
//! parked in a blocking `read` that BLOCKS the signal is not disturbed: its
//! read neither fails `EINTR` nor returns early, and completes on the later
//! write. Then the roles swap: the main thread blocks the signal, and the
//! worker — the one thread left that does not (the killing helper blocks it
//! too) — is interrupted in its read, the handler running on the worker.
//! Helpers wait until the threads are asleep in their reads and mark the
//! stream before they kill. (The family gate also reads this probe's recorded
//! trace: a generation that wakes more than one task fails it, even when the
//! extra task silently re-parks.)

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use serde_json::Value;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use syscall_conformance::calls::{neg, Probe};

    pub fn run(p: &Probe) {
        support::reset();
        support::install(SIGUSR1, 0, false);
        let pid = p.getpid() as pid_t;
        let main_tid = p.gettid() as pid_t;
        let usr1 = support::one_set(SIGUSR1);
        let (r, a) = p.pipe2(0);
        p.require("pipe for the main thread", r == 0);
        let (r, b) = p.pipe2(0);
        p.require("pipe for the worker", r == 0);

        let phase = AtomicI32::new(0);
        let released = AtomicBool::new(false);
        let worker_tid = AtomicI32::new(0);
        let await_phase = |wanted: i32| {
            p.rec.quiet(|| {
                for _ in 0..4000 {
                    if phase.load(Ordering::SeqCst) >= wanted || released.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let tid = support::gettid();
                p.check("worker blocks SIGUSR1", p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0);
                worker_tid.store(tid, Ordering::SeqCst);
                phase.store(1, Ordering::SeqCst);
                // Parked here across the first kill; only the main thread's
                // later write ends this read. Unrecorded, and reported in the
                // worker's next turn: the main thread is recording meanwhile,
                // and the stream's order must not depend on who runs first.
                let (n, data) = p.rec.quiet(|| p.read(b[0], 1));

                await_phase(3);
                p.check("a thread that blocks the signal is not disturbed: its read completes on the later write", n == 1 && data == b"w");
                p.check("and no handler ran on it", support::HANDLER_TID.load(Ordering::SeqCst) != tid);
                p.check("worker unblocks SIGUSR1", p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0);
                phase.store(4, Ordering::SeqCst);
                p.check("with the leader blocking it, the process-directed signal interrupts the worker's read", p.read(b[0], 1).0 == neg(EINTR));
                p.check("the handler ran on the worker", support::HANDLER_TID.load(Ordering::SeqCst) == tid && support::count() == 2);
                phase.store(5, Ordering::SeqCst);
            });
            let _release = support::Release(&released);

            await_phase(1);
            p.require("the worker is set up", phase.load(Ordering::SeqCst) >= 1);
            let worker = worker_tid.load(Ordering::SeqCst);
            scope.spawn(move || {
                // First kill: both threads asleep in their reads.
                support::until_parked(main_tid);
                support::until_parked(worker);
                p.mark("helper_kill", &[("sig", Value::from(SIGUSR1))]);
                unsafe {
                    kill(pid, SIGUSR1);
                }
            });
            p.check(
                "the leader's read is interrupted (it does not block the signal)",
                p.read(a[0], 1).0 == neg(EINTR),
            );
            p.check(
                "exactly one handler ran, on the main thread",
                support::count() == 1 && support::HANDLER_TID.load(Ordering::SeqCst) == main_tid,
            );
            p.check("main writes to the worker's pipe", p.write(b[1], b"w") == 1);

            p.check(
                "main blocks SIGUSR1",
                p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0,
            );
            phase.store(3, Ordering::SeqCst);
            await_phase(4);
            p.require("the worker unblocked", phase.load(Ordering::SeqCst) >= 4);
            scope.spawn(move || {
                // The helper blocks the signal itself, so the worker is the
                // only thread left that wants it.
                unsafe {
                    pthread_sigmask(SIG_BLOCK, &usr1, std::ptr::null_mut());
                }
                support::until_parked(worker);
                p.mark("helper_kill", &[("sig", Value::from(SIGUSR1))]);
                unsafe {
                    kill(pid, SIGUSR1);
                }
            });
            await_phase(5);
            p.require(
                "the worker was interrupted",
                phase.load(Ordering::SeqCst) >= 5,
            );
            let mut pending = support::empty_set();
            p.check("main rt_sigpending", p.rt_sigpending(&mut pending, 8) == 0);
            p.check(
                "the signal was delivered to the worker, not left pending for the blocking leader",
                !support::has(&pending, SIGUSR1),
            );
        });
        p.check("two handlers ran in all", support::count() == 2);
        p.check(
            "main unblocks SIGUSR1",
            p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0,
        );
        p.check("nothing was pending for it", support::count() == 2);
        for fd in [a[0], a[1], b[0], b[1]] {
            p.close(fd);
        }
    }
}

syscall_conformance::probe_main!("signal/one_wake", scenario::run);
