//! signal/mask — per-thread masks, pending bits, synchronous dequeue through
//! rt_sigtimedwait, and rt_sigsuspend's temporary mask plus EINTR return.

#[cfg(target_os = "linux")]
mod scenario {
    #[path = "support.rs"]
    mod support;

    use libc::*;
    use std::thread;
    use syscall_conformance::calls::{neg, Probe};

    pub fn run(p: &Probe) {
        support::install(SIGUSR2, 0, false);
        let pid = p.getpid() as pid_t;
        let blocked = support::one_set(SIGUSR2);
        let mut old = support::empty_set();
        p.check("block SIGUSR2", p.rt_sigprocmask(SIG_BLOCK, Some(&blocked), Some(&mut old), 8) == 0);
        p.check("SIGUSR2 was not already blocked", !support::has(&old, SIGUSR2));
        p.check("kill blocked SIGUSR2", p.kill(pid, SIGUSR2) == 0);
        let mut pending = support::empty_set();
        p.check("rt_sigpending succeeds", p.rt_sigpending(&mut pending, 8) == 0);
        p.check("blocked SIGUSR2 is pending", support::has(&pending, SIGUSR2));
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        p.check("rt_sigtimedwait dequeues SIGUSR2", p.rt_sigtimedwait(&blocked, Some(&mut info), Some(0), 8) == SIGUSR2 as i64);
        p.check("rt_sigtimedwait reports SI_USER", info.si_code == SI_USER);
        let mut pending2 = support::empty_set();
        p.rt_sigpending(&mut pending2, 8);
        p.check("SIGUSR2 is no longer pending", !support::has(&pending2, SIGUSR2));

        p.check("rt_sigtimedwait with no pending signal times out", p.rt_sigtimedwait(&blocked, Some(&mut info), Some(1_000_000), 8) == neg(EAGAIN));
        p.check("rt_sigprocmask size other than 8 is EINVAL", p.rt_sigprocmask(SIG_BLOCK, Some(&blocked), None, 4) == neg(EINVAL));

        let empty = support::empty_set();
        thread::spawn(move || {
            support::short_pause();
            unsafe { kill(pid, SIGUSR2); }
        });
        p.check("rt_sigsuspend returns EINTR after delivery", p.rt_sigsuspend(&empty, 8) == neg(EINTR));
        p.check("unblock SIGUSR2", p.rt_sigprocmask(SIG_UNBLOCK, Some(&blocked), None, 8) == 0);
    }
}

syscall_conformance::probe_main!("signal/mask", scenario::run);
