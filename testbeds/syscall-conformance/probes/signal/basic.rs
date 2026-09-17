//! signal/basic — handler delivery before kill(self) returns, SA_SIGINFO sender
//! fields for process-directed self signals, and rt_sigaction's reserved/invalid
//! vocabulary.

#[cfg(target_os = "linux")]
mod scenario {
    #[path = "support.rs"]
    mod support;

    use libc::*;
    use std::sync::atomic::Ordering;
    use syscall_conformance::calls::{neg, Probe};

    pub fn run(p: &Probe) {
        support::reset();
        support::install(SIGUSR1, SA_SIGINFO, true);
        let pid = p.getpid() as pid_t;
        let uid = p.getuid() as uid_t;
        p.check("kill(self, 0) probes existence", p.kill(pid, 0) == 0);
        p.check("handler count starts at zero", support::COUNT.load(Ordering::SeqCst) == 0);
        p.require("kill(self, SIGUSR1)", p.kill(pid, SIGUSR1) == 0);
        p.check("handler ran before kill returned", support::COUNT.load(Ordering::SeqCst) == 1);
        p.check("handler saw SIGUSR1", support::LAST_SIG.load(Ordering::SeqCst) == SIGUSR1);
        p.check("SA_SIGINFO si_code for kill is SI_USER", support::LAST_CODE.load(Ordering::SeqCst) == SI_USER);
        p.check("SA_SIGINFO si_pid is the sender pid", support::LAST_PID.load(Ordering::SeqCst) == pid);
        p.check("SA_SIGINFO si_uid is the sender uid", support::LAST_UID.load(Ordering::SeqCst) as uid_t == uid);

        let mut act: sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = support::handler as *const () as usize;
        unsafe { sigemptyset(&mut act.sa_mask); }
        p.require("rt_sigaction on SIGKILL is EINVAL", p.call_observed(syscall_conformance::vehicle::Sys::RtSigaction, [SIGKILL as i64, &act as *const sigaction as i64, 0, 8, 0, 0]) == neg(EINVAL));
        p.check("rt_sigaction on SIGSTOP is EINVAL", p.call_observed(syscall_conformance::vehicle::Sys::RtSigaction, [SIGSTOP as i64, &act as *const sigaction as i64, 0, 8, 0, 0]) == neg(EINVAL));
        p.check("rt_sigaction invalid signum is EINVAL", p.rt_sigaction_raw(999, 8) == neg(EINVAL));
        p.check("rt_sigaction sigset size other than 8 is EINVAL", p.rt_sigaction_raw(SIGUSR1, 4) == neg(EINVAL));
    }
}

syscall_conformance::probe_main!("signal/basic", scenario::run);
