//! thread/pthread_kill — glibc's `pthread_kill` (a `tgkill` on the target's
//! tid; a libc-only symbol, so this scenario runs through the libc vehicle
//! alone): the handler runs on the target thread; to self it is synchronous;
//! signal 0 probes; a signal past SIGRTMAX is EINVAL (returned, not errno).

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{Probe, neg};
use libc::*;
use std::sync::atomic::{AtomicU64, Ordering};

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
    let turns = support::Turns::default();
    let worker_pthread = AtomicU64::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            // Published before the tid, which the main thread waits for.
            worker_pthread.store(unsafe { pthread_self() } as u64, Ordering::SeqCst);
            turns.worker_starts();
            turns.hold();
        });
        let _release = turns.release_guard();
        let worker = turns.await_worker(p);
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
    });
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/pthread_kill",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_getpid, Syscall::N_gettid, Syscall::N_tgkill],
    symbols: &["getpid", "syscall", "sigaction", "pthread_kill"],
    trace: Some(TraceFacts {
        generations: &[Generation::thread(SIGUSR1), Generation::thread(SIGUSR1)],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
