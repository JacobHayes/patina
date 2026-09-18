//! signal/basic — a signal to self is delivered before `kill`/`tkill`/`tgkill`
//! returns, with the `SA_SIGINFO` sender fields the kernel fills (`SI_USER`
//! for kill, `SI_TKILL` for the thread-directed rows), and the errno
//! vocabulary of `kill` and `rt_sigaction` (man 2 kill, man 2 rt_sigaction).

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use std::sync::atomic::Ordering;
    use syscall_conformance::calls::{neg, Probe};
    use syscall_conformance::vehicle::Sys;

    pub fn run(p: &Probe) {
        support::reset();
        support::install(SIGUSR1, SA_SIGINFO, true);
        let pid = p.getpid() as pid_t;
        let tid = p.gettid() as pid_t;
        let uid = p.getuid() as uid_t;
        p.check("kill(self, 0) probes existence", p.kill(pid, 0) == 0);
        p.check("handler count starts at zero", support::count() == 0);
        p.require("kill(self, SIGUSR1)", p.kill(pid, SIGUSR1) == 0);
        p.check("handler ran before kill returned", support::count() == 1);
        p.check(
            "handler saw SIGUSR1",
            support::LAST_SIG.load(Ordering::SeqCst) == SIGUSR1,
        );
        p.check(
            "SA_SIGINFO si_code for kill is SI_USER",
            support::LAST_CODE.load(Ordering::SeqCst) == SI_USER,
        );
        p.check(
            "SA_SIGINFO si_pid is the sender pid",
            support::LAST_PID.load(Ordering::SeqCst) == pid,
        );
        p.check(
            "SA_SIGINFO si_uid is the sender uid",
            support::LAST_UID.load(Ordering::SeqCst) as uid_t == uid,
        );
        p.check(
            "the handler ran on the calling thread",
            support::HANDLER_TID.load(Ordering::SeqCst) == tid,
        );

        p.check("tgkill(self) delivers", p.tgkill(pid, tid, SIGUSR1) == 0);
        p.check("handler ran before tgkill returned", support::count() == 2);
        p.check(
            "SA_SIGINFO si_code for tgkill is SI_TKILL",
            support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
        );
        p.check("tkill(self) delivers", p.tkill(tid, SIGUSR1) == 0);
        p.check("handler ran before tkill returned", support::count() == 3);
        p.check(
            "SA_SIGINFO si_code for tkill is SI_TKILL",
            support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
        );

        p.check(
            "kill with a signal past SIGRTMAX is EINVAL",
            p.kill(pid, 65) == neg(EINVAL),
        );
        p.check(
            "kill with a negative signal is EINVAL",
            p.kill(pid, -3) == neg(EINVAL),
        );
        p.check(
            "kill of a pid that does not exist is ESRCH",
            p.kill(99_999_999, SIGUSR1) == neg(ESRCH),
        );
        p.check(
            "tgkill with a tid of 0 is EINVAL",
            p.tgkill(pid, 0, SIGUSR1) == neg(EINVAL),
        );
        p.check(
            "tkill with a tid of 0 is EINVAL",
            p.tkill(0, SIGUSR1) == neg(EINVAL),
        );
        p.check(
            "tgkill of a tid outside the thread group is ESRCH",
            p.tgkill(pid, 99_999_999, SIGUSR1) == neg(ESRCH),
        );
        p.check(
            "handler count is unchanged by the refused sends",
            support::count() == 3,
        );

        let mut act: sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = support::handler as *const () as usize;
        unsafe {
            sigemptyset(&mut act.sa_mask);
        }
        p.require(
            "rt_sigaction on SIGKILL is EINVAL",
            p.call_observed(
                Sys::RtSigaction,
                [SIGKILL as i64, &act as *const sigaction as i64, 0, 8, 0, 0],
            ) == neg(EINVAL),
        );
        p.check(
            "rt_sigaction on SIGSTOP is EINVAL",
            p.call_observed(
                Sys::RtSigaction,
                [SIGSTOP as i64, &act as *const sigaction as i64, 0, 8, 0, 0],
            ) == neg(EINVAL),
        );
        p.check(
            "rt_sigaction invalid signum is EINVAL",
            p.rt_sigaction_raw(999, 8) == neg(EINVAL),
        );
        p.check(
            "rt_sigaction sigset size other than 8 is EINVAL",
            p.rt_sigaction_raw(SIGUSR1, 4) == neg(EINVAL),
        );
    }
}

syscall_conformance::probe_main!("signal/basic", scenario::run);
