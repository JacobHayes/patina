//! thread/masks — the signal mask is per thread and the pending set has a
//! per-thread part: a process-directed signal goes to a thread that does not
//! block it (kernel/signal.c complete_signal: the current thread if eligible,
//! else a thread whose mask allows it), a thread-directed signal to a thread
//! that blocks it stays pending for that thread alone (not visible in another
//! thread's `rt_sigpending`), and is delivered on THAT thread when it unblocks.

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use std::sync::atomic::{AtomicI32, Ordering};
    use syscall_conformance::calls::Probe;

    pub fn run(p: &Probe) {
        support::reset();
        support::install(SIGUSR1, SA_SIGINFO, true);
        let pid = p.getpid() as pid_t;
        let main_tid = p.gettid() as pid_t;
        let usr1 = support::one_set(SIGUSR1);
        let worker_tid = AtomicI32::new(0);
        // 0 = worker blocking and idle, 1 = worker asked to unblock, 2 = worker
        // has unblocked (and recorded what that delivered), 3 = worker may exit.
        let phase = AtomicI32::new(0);
        let released = std::sync::atomic::AtomicBool::new(false);
        let await_phase = |wanted: i32| {
            p.rec.quiet(|| {
                for _ in 0..500 {
                    if phase.load(Ordering::SeqCst) >= wanted || released.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            })
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                // The worker blocks SIGUSR1 on its own thread only.
                p.check("worker blocks SIGUSR1", p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0);
                worker_tid.store(support::gettid(), Ordering::SeqCst);
                await_phase(1);
                let before = support::count();
                p.check("worker unblocks SIGUSR1", p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0);
                p.check("the pending thread-directed signal was delivered on the worker before its rt_sigprocmask returned",
                    support::count() == before + 1 && support::HANDLER_TID.load(Ordering::SeqCst) == support::gettid());
                phase.store(2, Ordering::SeqCst);
                await_phase(3);
            });
            // A failed check panics natively (`--strict`); releasing the worker
            // on the way out keeps the scope's join from hanging.
            let _release = support::Release(&released);
            p.rec.quiet(|| {
                for _ in 0..2000 {
                    if worker_tid.load(Ordering::SeqCst) != 0 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            });
            p.require(
                "the worker reported its tid",
                worker_tid.load(Ordering::SeqCst) != 0,
            );
            let worker = worker_tid.load(Ordering::SeqCst);
            let mut mine = support::empty_set();
            p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut mine), 8);
            p.check(
                "the main thread's mask is unaffected by the worker's block",
                !support::has(&mine, SIGUSR1),
            );

            p.check(
                "kill(self) process-directed while the worker blocks it",
                p.kill(pid, SIGUSR1) == 0,
            );
            p.check(
                "it was delivered synchronously to the sender, the one thread not blocking it",
                support::count() == 1,
            );
            p.check(
                "on the main thread",
                support::HANDLER_TID.load(Ordering::SeqCst) == main_tid,
            );

            p.check(
                "main blocks SIGUSR1 too",
                p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0,
            );
            p.check(
                "tgkill to the worker while it blocks",
                p.tgkill(pid, worker, SIGUSR1) == 0,
            );
            p.rec
                .quiet(|| std::thread::sleep(std::time::Duration::from_millis(40)));
            p.check(
                "a thread-directed signal to a blocking thread stays pending",
                support::count() == 1,
            );
            let mut pending = support::empty_set();
            p.check(
                "rt_sigpending on the main thread",
                p.rt_sigpending(&mut pending, 8) == 0,
            );
            p.check(
                "the worker's pending signal is not in the main thread's pending set",
                !support::has(&pending, SIGUSR1),
            );
            p.check(
                "main unblocks SIGUSR1 while the worker still blocks",
                p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0,
            );
            p.check(
                "unblocking on the main thread delivers nothing (the signal belongs to the worker)",
                support::count() == 1,
            );

            phase.store(1, Ordering::SeqCst);
            await_phase(2);
            p.check(
                "the worker's unmask delivered the thread-directed signal",
                support::count() == 2,
            );
            p.check(
                "on the worker",
                support::HANDLER_TID.load(Ordering::SeqCst) == worker,
            );
            p.check(
                "with SI_TKILL",
                support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
            );
            phase.store(3, Ordering::SeqCst);
        });
    }
}

syscall_conformance::probe_main!("thread/masks", scenario::run);
