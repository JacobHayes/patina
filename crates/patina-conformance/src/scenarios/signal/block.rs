//! signal/block — the waits that park until a signal exists must not return
//! before one does: `pause` returns `EINTR` only after a handled signal ran
//! (kernel/signal.c: pause → -ERESTARTNOHAND → EINTR under a handler), a
//! `rt_sigtimedwait` with no timeout parks until a matching signal is
//! generated, a handled signal outside its set interrupts it with `EINTR`
//! after the handler, and a blocking `signalfd` read parks until a matching
//! signal is pending (fs/signalfd.c signalfd_dequeue: schedule() until
//! next_signal), and `rt_sigsuspend` atomically installs its mask, parks
//! until a handled signal is delivered, returns `EINTR` and restores the
//! previous mask, where a signal the temporary mask still blocks does not
//! wake it (man 2 sigsuspend, kernel/signal.c sigsuspend:
//! set_current_blocked + schedule until signal_pending). Each helper marks
//! the stream (`helper_kill`) immediately before it kills, so a wait that
//! returned early shows up as the wait's event preceding the mark, and the
//! handler count at return is checked.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};

use crate::signals as support;

use crate::observe::Norm;
use crate::probe::{Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::mem::size_of;
use std::sync::atomic::Ordering;
use std::thread;

/// A helper that, for each of `sigs` in turn, waits until the calling
/// (main) thread is parked, marks the stream and kills.
fn delayed_kills<'a>(
    scope: &'a thread::Scope<'a, '_>,
    p: &'a Probe,
    pid: pid_t,
    sigs: &'static [c_int],
) {
    let main_tid = support::gettid();
    scope.spawn(move || {
        for &sig in sigs {
            support::until_parked(main_tid);
            p.mark("helper_kill", &[("sig", Value::from(sig))]);
            unsafe {
                kill(pid, sig);
            }
        }
    });
}

pub fn run(p: &Probe) {
    support::reset();
    let pid = p.getpid() as pid_t;
    support::install(SIGUSR1, 0, false);

    thread::scope(|scope| {
        delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.check(
            "pause returns EINTR once a handled signal was delivered",
            p.pause() == neg(EINTR),
        );
    });
    p.check(
        "the handler ran before pause returned",
        support::count() == 1,
    );

    let usr2 = support::one_set(SIGUSR2);
    p.check(
        "block SIGUSR2",
        p.rt_sigprocmask(SIG_BLOCK, Some(&usr2), None, 8) == 0,
    );
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    thread::scope(|scope| {
        delayed_kills(scope, p, pid, &[SIGUSR2]);
        p.check(
            "rt_sigtimedwait without a timeout parks until the helper's signal",
            p.rt_sigtimedwait(&usr2, Some(&mut info), None, 8) == SIGUSR2 as i64,
        );
    });
    p.check(
        "it reports the sender code SI_USER",
        info.si_code == SI_USER,
    );
    p.check(
        "no handler ran for the dequeued signal",
        support::count() == 1,
    );

    thread::scope(|scope| {
        delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.check(
            "a handled signal outside the set interrupts rt_sigtimedwait with EINTR",
            p.rt_sigtimedwait(&usr2, Some(&mut info), None, 8) == neg(EINTR),
        );
    });
    p.check(
        "that handler ran before the wait returned",
        support::count() == 2,
    );

    let sfd = p.signalfd4(-1, &usr2, 0);
    p.require("blocking signalfd", sfd >= 0);
    let mut ssi: signalfd_siginfo = unsafe { std::mem::zeroed() };
    thread::scope(|scope| {
        delayed_kills(scope, p, pid, &[SIGUSR2]);
        let n = p.call_unrecorded(
            Syscall::N_read,
            [
                sfd as i64,
                &mut ssi as *mut signalfd_siginfo as i64,
                size_of::<signalfd_siginfo>() as i64,
                0,
                0,
                0,
            ],
        );
        p.rec
            .event("read", n)
            .arg("fd", sfd)
            .norm("args.fd", Norm::Relative("fd"))
            .arg("len", size_of::<signalfd_siginfo>())
            .emit();
        p.check(
            "a blocking signalfd read parks until a matching signal is pending",
            n == size_of::<signalfd_siginfo>() as i64,
        );
    });
    p.check(
        "the read dequeued the helper's signal",
        ssi.ssi_signo == SIGUSR2 as u32 && ssi.ssi_code == SI_USER,
    );
    p.check(
        "no handler ran for the signalfd-dequeued signal",
        support::count() == 2,
    );
    p.close(sfd);

    // rt_sigsuspend(&empty): SIGUSR2 becomes deliverable and is handled.
    support::install(SIGUSR2, 0, false);
    let empty = support::empty_set();
    thread::scope(|scope| {
        delayed_kills(scope, p, pid, &[SIGUSR2]);
        p.check(
            "rt_sigsuspend returns EINTR after delivery",
            p.rt_sigsuspend(&empty, 8) == neg(EINTR),
        );
    });
    p.check(
        "the handler ran exactly once, during the suspend",
        support::count() == 3 && support::LAST_SIG.load(Ordering::SeqCst) == SIGUSR2,
    );
    let mut restored = support::empty_set();
    p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut restored), 8);
    p.check(
        "rt_sigsuspend restored the previous mask (SIGUSR2 blocked again)",
        support::has(&restored, SIGUSR2),
    );

    // rt_sigsuspend(&{SIGUSR2}): SIGUSR2 stays blocked in the temporary mask,
    // so the helper's first kill only makes it pending; its second (SIGUSR1,
    // handled, unblocked) is what ends the suspend.
    thread::scope(|scope| {
        delayed_kills(scope, p, pid, &[SIGUSR2, SIGUSR1]);
        p.check(
            "rt_sigsuspend with the signal still blocked waits for an unblocked one",
            p.rt_sigsuspend(&usr2, 8) == neg(EINTR),
        );
    });
    p.check(
        "only SIGUSR1 ran a handler",
        support::count() == 4 && support::LAST_SIG.load(Ordering::SeqCst) == SIGUSR1,
    );
    let mut still = support::empty_set();
    p.rt_sigpending(&mut still, 8);
    p.check(
        "the blocked SIGUSR2 is still pending after the suspend",
        support::has(&still, SIGUSR2),
    );
    p.check(
        "it dequeues afterwards",
        p.rt_sigtimedwait(&usr2, Some(&mut info), Some(0), 8) == SIGUSR2 as i64,
    );
    p.check(
        "unblock SIGUSR2",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr2), None, 8) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/block",
    run,
    covers: &[
        Syscall::N_getpid,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_pause,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigpending,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_rt_sigsuspend,
        Syscall::N_signalfd4,
        Syscall::N_read,
        Syscall::N_close,
        Syscall::N_kill,
    ],
    symbols: &[
        "getpid",
        "pause",
        "read",
        "close",
        "kill",
        "sigaction",
        "syscall",
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
