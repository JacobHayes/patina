//! signal/mask — the thread mask and the pending set: a blocked signal stays
//! pending (`rt_sigpending`), is dequeued synchronously by `rt_sigtimedwait`,
//! a timed wait with nothing pending is `EAGAIN` after the timeout, and
//! `rt_sigsuspend` atomically installs its mask, parks until a handled signal
//! is delivered (never returning before the helper's kill — the helper's
//! `helper_kill` mark precedes the return in the stream, and the handler count
//! is 1 at return), returns `EINTR`, and restores the previous mask; a signal
//! the temporary mask still blocks does not wake it (man 2 sigsuspend,
//! kernel/signal.c sigsuspend: set_current_blocked + schedule until
//! signal_pending).

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{Probe, neg};
use libc::*;
use serde_json::Value;
use std::thread;

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR2, 0, false);
    support::install(SIGUSR1, 0, false);
    let pid = p.getpid() as pid_t;
    let blocked = support::one_set(SIGUSR2);
    let mut old = support::empty_set();
    p.check(
        "block SIGUSR2",
        p.rt_sigprocmask(SIG_BLOCK, Some(&blocked), Some(&mut old), 8) == 0,
    );
    p.check(
        "SIGUSR2 was not already blocked",
        !support::has(&old, SIGUSR2),
    );
    p.check("kill blocked SIGUSR2", p.kill(pid, SIGUSR2) == 0);
    p.check(
        "a blocked signal does not run its handler",
        support::count() == 0,
    );
    let mut pending = support::empty_set();
    p.check(
        "rt_sigpending succeeds",
        p.rt_sigpending(&mut pending, 8) == 0,
    );
    p.check(
        "blocked SIGUSR2 is pending",
        support::has(&pending, SIGUSR2),
    );
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    p.check(
        "rt_sigtimedwait dequeues SIGUSR2",
        p.rt_sigtimedwait(&blocked, Some(&mut info), Some(0), 8) == SIGUSR2 as i64,
    );
    p.check("rt_sigtimedwait reports SI_USER", info.si_code == SI_USER);
    p.check(
        "the dequeued signal did not run its handler",
        support::count() == 0,
    );
    let mut pending2 = support::empty_set();
    p.rt_sigpending(&mut pending2, 8);
    p.check(
        "SIGUSR2 is no longer pending",
        !support::has(&pending2, SIGUSR2),
    );

    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "rt_sigtimedwait with no pending signal times out",
        p.rt_sigtimedwait(&blocked, Some(&mut info), Some(10_000_000), 8) == neg(EAGAIN),
    );
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the timed wait advanced the clock by at least its timeout",
        after - before >= 10_000_000,
    );
    p.check(
        "rt_sigprocmask size other than 8 is EINVAL",
        p.rt_sigprocmask(SIG_BLOCK, Some(&blocked), None, 4) == neg(EINVAL),
    );
    p.check(
        "rt_sigprocmask with an unknown how is EINVAL",
        p.rt_sigprocmask(99, Some(&blocked), None, 8) == neg(EINVAL),
    );
    p.check(
        "rt_sigpending with a sigset size larger than the kernel's is EINVAL",
        p.rt_sigpending(&mut pending, 16) == neg(EINVAL),
    );

    // sigsuspend(&empty): SIGUSR2 becomes deliverable; the helper marks the
    // stream, then kills. The suspend must not return before that mark.
    let empty = support::empty_set();
    let main_tid = support::gettid();
    thread::scope(|scope| {
        scope.spawn(|| {
            support::until_parked(main_tid);
            p.mark("helper_kill", &[("sig", Value::from(SIGUSR2))]);
            unsafe {
                kill(pid, SIGUSR2);
            }
        });
        p.check(
            "rt_sigsuspend returns EINTR after delivery",
            p.rt_sigsuspend(&empty, 8) == neg(EINTR),
        );
    });
    p.check(
        "the handler ran exactly once, during the suspend",
        support::count() == 1
            && support::LAST_SIG.load(std::sync::atomic::Ordering::SeqCst) == SIGUSR2,
    );
    let mut restored = support::empty_set();
    p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut restored), 8);
    p.check(
        "rt_sigsuspend restored the previous mask (SIGUSR2 blocked again)",
        support::has(&restored, SIGUSR2),
    );

    // sigsuspend(&{SIGUSR2}): SIGUSR2 stays blocked in the temporary mask,
    // so the helper's first kill only makes it pending; its second kill
    // (SIGUSR1, handled, unblocked) is what ends the suspend.
    let keep_usr2 = support::one_set(SIGUSR2);
    thread::scope(|scope| {
        scope.spawn(|| {
            support::until_parked(main_tid);
            p.mark("helper_kill", &[("sig", Value::from(SIGUSR2))]);
            unsafe {
                kill(pid, SIGUSR2);
            }
            support::until_parked(main_tid);
            p.mark("helper_kill", &[("sig", Value::from(SIGUSR1))]);
            unsafe {
                kill(pid, SIGUSR1);
            }
        });
        p.check(
            "rt_sigsuspend with the signal still blocked waits for an unblocked one",
            p.rt_sigsuspend(&keep_usr2, 8) == neg(EINTR),
        );
    });
    p.check(
        "only SIGUSR1 ran a handler",
        support::count() == 2
            && support::LAST_SIG.load(std::sync::atomic::Ordering::SeqCst) == SIGUSR1,
    );
    let mut still = support::empty_set();
    p.rt_sigpending(&mut still, 8);
    p.check(
        "the blocked SIGUSR2 is still pending after the suspend",
        support::has(&still, SIGUSR2),
    );
    p.check(
        "it dequeues afterwards",
        p.rt_sigtimedwait(&blocked, Some(&mut info), Some(0), 8) == SIGUSR2 as i64,
    );
    p.check(
        "unblock SIGUSR2",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&blocked), None, 8) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/mask",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_rt_sigprocmask,
        Syscall::N_kill,
        Syscall::N_rt_sigpending,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_rt_sigsuspend,
        Syscall::N_clock_gettime,
    ],
    symbols: &["getpid", "kill", "sigaction", "syscall", "clock_gettime"],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
