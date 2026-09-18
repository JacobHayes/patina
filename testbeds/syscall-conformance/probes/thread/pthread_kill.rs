//! thread/pthread_kill — glibc's `pthread_kill` (a `tgkill` on the target's
//! tid; a libc-only symbol, so this probe runs through the libc vehicle
//! alone): the handler runs on the target thread; to self it is synchronous;
//! signal 0 probes; a signal past SIGRTMAX is EINVAL (returned, not errno).

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
    use syscall_conformance::calls::{neg, Probe};

    fn pthread_kill_recorded(p: &Probe, thread: pthread_t, sig: c_int, target: &str) -> i64 {
        // pthread_kill returns the error number directly (never sets errno).
        let code = unsafe { pthread_kill(thread, sig) };
        let result = if code == 0 { 0 } else { -(code as i64) };
        p.rec
            .event("pthread_kill", result)
            .arg("target", target)
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn run(p: &Probe) {
        support::reset();
        support::install(SIGUSR1, SA_SIGINFO, true);
        let main_tid = p.gettid() as pid_t;
        let worker_tid = AtomicI32::new(0);
        let worker_pthread = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                worker_pthread.store(unsafe { pthread_self() } as u64, Ordering::SeqCst);
                worker_tid.store(support::gettid(), Ordering::SeqCst);
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            });
            let _release = support::Release(&stop);
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
            let handle = worker_pthread.load(Ordering::SeqCst) as pthread_t;
            p.check(
                "pthread_kill(worker, SIGUSR1)",
                pthread_kill_recorded(p, handle, SIGUSR1, "worker") == 0,
            );
            support::wait_for_count(p, 1);
            p.check("the handler ran once", support::count() == 1);
            p.check(
                "on the worker",
                support::HANDLER_TID.load(Ordering::SeqCst) == worker,
            );
            p.check(
                "with SI_TKILL",
                support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
            );
            p.check(
                "pthread_kill(self, SIGUSR1)",
                pthread_kill_recorded(p, unsafe { pthread_self() }, SIGUSR1, "self") == 0,
            );
            p.check(
                "to self it is delivered before pthread_kill returns",
                support::count() == 2,
            );
            p.check(
                "on the main thread",
                support::HANDLER_TID.load(Ordering::SeqCst) == main_tid,
            );
            p.check(
                "pthread_kill(worker, 0) probes",
                pthread_kill_recorded(p, handle, 0, "worker") == 0,
            );
            p.check(
                "pthread_kill past SIGRTMAX is EINVAL",
                pthread_kill_recorded(p, handle, 65, "worker") == neg(EINVAL),
            );
            p.check("the probes delivered nothing", support::count() == 2);
            stop.store(true, Ordering::SeqCst);
        });
    }
}

syscall_conformance::probe_main!("thread/pthread_kill", scenario::run, libc);
