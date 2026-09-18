//! signal/unmask — a signal that was pending while blocked is delivered on
//! the syscall that unblocks it, before that syscall returns (kernel:
//! rt_sigprocmask → set_current_blocked → recalc_sigpending, and the pending
//! signal is handled on the return to user mode), for `SIG_UNBLOCK` and
//! `SIG_SETMASK`, for a process-directed (`SI_USER`) and a thread-directed
//! (`SI_TKILL`) signal; when several standard signals are unblocked at once
//! the lowest-numbered is dequeued first (kernel/signal.c next_signal) and a
//! frame is set up for each before returning to user mode
//! (exit_to_user_mode_loop re-runs arch_do_signal_or_restart while a signal
//! is pending), so the handlers run in reverse dequeue order, each inner one
//! under the outer frame's mask.

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use std::sync::atomic::Ordering;
    use syscall_conformance::calls::Probe;

    pub fn run(p: &Probe) {
        support::reset();
        support::install(SIGUSR1, SA_SIGINFO, true);
        support::install(SIGUSR2, SA_SIGINFO, true);
        let pid = p.getpid() as pid_t;
        let tid = p.gettid() as pid_t;
        let usr1 = support::one_set(SIGUSR1);
        let both = support::set_of(&[SIGUSR1, SIGUSR2]);

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
}

syscall_conformance::probe_main!("signal/unmask", scenario::run);
