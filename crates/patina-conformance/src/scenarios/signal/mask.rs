//! signal/mask — the thread mask and the pending set: a blocked signal stays
//! pending (`rt_sigpending`) and runs no handler, is dequeued synchronously
//! by `rt_sigtimedwait` (a timed wait with nothing pending is `EAGAIN` after
//! the timeout), and is otherwise delivered on the syscall that unblocks
//! it, before that syscall returns (kernel: rt_sigprocmask →
//! set_current_blocked → recalc_sigpending, and the pending signal is
//! handled on the return to user mode), for `SIG_UNBLOCK` and
//! `SIG_SETMASK`, for a process-directed (`SI_USER`) and a thread-directed
//! (`SI_TKILL`) signal; when several standard signals are unblocked at once
//! the lowest-numbered is dequeued first (kernel/signal.c next_signal) and a
//! frame is set up for each before returning to user mode
//! (exit_to_user_mode_loop re-runs arch_do_signal_or_restart while a signal
//! is pending), so the handlers run in reverse dequeue order, each inner one
//! under the outer frame's mask; and the errno vocabulary of
//! `rt_sigprocmask` and `rt_sigpending`.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{Probe, neg};
use libc::*;
use std::sync::atomic::Ordering;

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, SA_SIGINFO, true);
    support::install(SIGUSR2, SA_SIGINFO, true);
    let pid = p.getpid() as pid_t;
    let tid = p.gettid() as pid_t;
    let usr1 = support::one_set(SIGUSR1);
    let both = support::set_of(&[SIGUSR1, SIGUSR2]);
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

    p.check(
        "block SIGUSR1",
        p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0,
    );
    p.check(
        "kill(self, SIGUSR1) while blocked",
        p.kill(pid, SIGUSR1) == 0,
    );
    p.check("nothing was delivered while blocked", support::count() == 0);
    let mut pending = support::empty_set();
    p.rt_sigpending(&mut pending, 8);
    p.check("it is pending", support::has(&pending, SIGUSR1));
    p.check(
        "SIG_UNBLOCK",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0,
    );
    p.check(
        "the pending signal was delivered before rt_sigprocmask returned",
        support::count() == 1,
    );
    p.check(
        "with SI_USER",
        support::LAST_CODE.load(Ordering::SeqCst) == SI_USER,
    );
    p.check(
        "on the unblocking thread",
        support::HANDLER_TID.load(Ordering::SeqCst) == tid,
    );
    p.rt_sigpending(&mut pending, 8);
    p.check("it is no longer pending", !support::has(&pending, SIGUSR1));

    p.check(
        "block SIGUSR1 again",
        p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0,
    );
    p.check(
        "tgkill(self, SIGUSR1) while blocked",
        p.tgkill(pid, tid, SIGUSR1) == 0,
    );
    p.check("still nothing delivered", support::count() == 1);
    let empty = support::empty_set();
    p.check(
        "SIG_SETMASK to the empty set",
        p.rt_sigprocmask(SIG_SETMASK, Some(&empty), None, 8) == 0,
    );
    p.check(
        "the thread-directed signal was delivered before rt_sigprocmask returned",
        support::count() == 2,
    );
    p.check(
        "with SI_TKILL",
        support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
    );

    support::reset();
    p.check(
        "block SIGUSR1 and SIGUSR2",
        p.rt_sigprocmask(SIG_BLOCK, Some(&both), None, 8) == 0,
    );
    p.check("kill(self, SIGUSR2)", p.kill(pid, SIGUSR2) == 0);
    p.check("kill(self, SIGUSR1)", p.kill(pid, SIGUSR1) == 0);
    p.check(
        "unblock both at once",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&both), None, 8) == 0,
    );
    p.check("both were delivered on the unmask", support::count() == 2);
    // The kernel dequeues the lowest-numbered signal first and sets up a
    // frame for EVERY deliverable pending signal before returning to user
    // mode, so the frames nest: SIGUSR2's handler runs first, on top of
    // SIGUSR1's frame, with SIGUSR1 blocked (the outer frame's mask), and
    // SIGUSR1's handler runs after SIGUSR2's sigreturn.
    p.check(
        "handlers of signals unblocked together run in reverse dequeue order (stacked frames)",
        support::order() == vec![SIGUSR2, SIGUSR1],
    );
    p.check("the inner handler (SIGUSR2) runs with SIGUSR1 blocked by the outer frame; the outer runs with neither", support::entry_masks() == vec![(true, true), (true, false)]);
    p.check(
        "rt_sigprocmask with a NULL set only reads",
        p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut pending), 8) == 0,
    );
    p.check(
        "the read-back mask has neither blocked",
        !support::has(&pending, SIGUSR1) && !support::has(&pending, SIGUSR2),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/mask",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_rt_sigprocmask,
        Syscall::N_kill,
        Syscall::N_tgkill,
        Syscall::N_rt_sigpending,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_clock_gettime,
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
            Generation::thread(SIGUSR1),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
