//! thread/kill — `tgkill`/`tkill` are thread-directed: the handler runs on
//! the named thread (recorded through `gettid()` inside the handler), not on
//! the sender; a thread-directed signal to self is synchronous; the tgid must
//! be the caller's thread group and the tid a live thread of it (man 2 tgkill:
//! ESRCH; EINVAL for a tid ≤ 0).

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{Probe, neg};
use libc::*;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, SA_SIGINFO, true);
    let pid = p.getpid() as pid_t;
    let main_tid = p.gettid() as pid_t;
    let tid_slot = AtomicI32::new(0);
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            tid_slot.store(support::gettid(), Ordering::SeqCst);
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        // A failed check panics natively (`--strict`); the guard releases
        // the worker on the way out so the scope's join cannot hang.
        let _release = support::Release(&stop);
        p.rec.quiet(|| {
            support::wait_until(std::time::Duration::from_millis(1), || {
                tid_slot.load(Ordering::SeqCst) != 0
            });
        });
        p.require(
            "the worker reported its tid",
            tid_slot.load(Ordering::SeqCst) != 0,
        );
        let worker = tid_slot.load(Ordering::SeqCst);
        p.check("the worker has its own tid", worker != main_tid);

        p.check("tgkill to the worker", p.tgkill(pid, worker, SIGUSR1) == 0);
        support::wait_for_count(p, 1);
        p.check(
            "tgkill delivered exactly one handler",
            support::count() == 1,
        );
        p.check(
            "the handler ran on the worker, not the sender",
            support::HANDLER_TID.load(Ordering::SeqCst) == worker,
        );
        p.check(
            "with SI_TKILL",
            support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
        );

        p.check("tkill to the worker", p.tkill(worker, SIGUSR1) == 0);
        support::wait_for_count(p, 2);
        p.check("tkill delivered another handler", support::count() == 2);
        p.check(
            "again on the worker",
            support::HANDLER_TID.load(Ordering::SeqCst) == worker,
        );

        p.check(
            "tgkill to the main thread from the main thread",
            p.tgkill(pid, main_tid, SIGUSR1) == 0,
        );
        p.check(
            "a thread-directed signal to self is delivered before tgkill returns",
            support::count() == 3,
        );
        p.check(
            "on the main thread",
            support::HANDLER_TID.load(Ordering::SeqCst) == main_tid,
        );

        p.check(
            "tgkill with signal 0 probes the worker",
            p.tgkill(pid, worker, 0) == 0,
        );
        p.check(
            "tgkill with the wrong tgid is ESRCH",
            p.tgkill(99_999_999, worker, SIGUSR1) == neg(ESRCH),
        );
        p.check(
            "tgkill with a negative tid is EINVAL",
            p.tgkill(pid, -1, SIGUSR1) == neg(EINVAL),
        );
        p.check("no probe delivered anything", support::count() == 3);
        stop.store(true, Ordering::SeqCst);
    });
    let worker = tid_slot.load(Ordering::SeqCst);
    // The join returns when the kernel cleared the thread's tid word,
    // which precedes the task's release; wait (unobserved) until the tid
    // is really gone before pinning ESRCH.
    p.rec.quiet(|| {
        support::wait_until(std::time::Duration::from_millis(1), || {
            p.tgkill(pid, worker, 0) == neg(ESRCH)
        });
    });
    p.check(
        "tgkill of a dead tid is ESRCH",
        p.tgkill(pid, worker, SIGUSR1) == neg(ESRCH),
    );
    p.check(
        "tkill of a dead tid is ESRCH",
        p.tkill(worker, SIGUSR1) == neg(ESRCH),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/kill",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_tgkill,
        Syscall::N_tkill,
    ],
    symbols: &["getpid", "syscall", "sigaction"],
    trace: Some(TraceFacts {
        generations: &[
            Generation::thread(SIGUSR1),
            Generation::thread(SIGUSR1),
            Generation::thread(SIGUSR1),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
