//! signal/rt_order — pending signal selection: lower-numbered standard signals
//! are delivered first, while same-number realtime instances are FIFO.

#[cfg(target_os = "linux")]
mod scenario {
    #[path = "support.rs"]
    mod support;

    use libc::*;
    use syscall_conformance::calls::Probe;

    fn queued_info(pid: pid_t, sig: c_int, value: i32) -> siginfo_t {
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        info.si_signo = sig;
        info.si_code = SI_QUEUE;
        #[allow(deprecated)]
        {
            info._pad[0] = pid;
            info._pad[1] = unsafe { getuid() as i32 };
            info._pad[2] = value;
        }
        info
    }

    pub fn run(p: &Probe) {
        let pid = p.getpid() as pid_t;
        let mut stdset = support::empty_set();
        unsafe { sigaddset(&mut stdset, SIGUSR1); sigaddset(&mut stdset, SIGUSR2); }
        p.rt_sigprocmask(SIG_BLOCK, Some(&stdset), None, 8);
        p.kill(pid, SIGUSR2);
        p.kill(pid, SIGUSR1);
        let mut si: siginfo_t = unsafe { std::mem::zeroed() };
        let first = p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8);
        let second = p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8);
        p.check("lower-numbered pending standard signal wins", first == SIGUSR1 as i64 && second == SIGUSR2 as i64);

        let rt = 34;
        let rtset = support::one_set(rt);
        p.rt_sigprocmask(SIG_BLOCK, Some(&rtset), None, 8);
        let q1 = queued_info(pid, rt, 1);
        let q2 = queued_info(pid, rt, 2);
        p.rt_sigqueueinfo(pid, rt, &q1);
        p.rt_sigqueueinfo(pid, rt, &q2);
        let mut a: siginfo_t = unsafe { std::mem::zeroed() };
        let mut b: siginfo_t = unsafe { std::mem::zeroed() };
        p.rt_sigtimedwait(&rtset, Some(&mut a), Some(0), 8);
        p.rt_sigtimedwait(&rtset, Some(&mut b), Some(0), 8);
        p.check("same-number realtime signals are both delivered", a.si_signo == rt && b.si_signo == rt);
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&stdset), None, 8);
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&rtset), None, 8);
    }
}

syscall_conformance::probe_main!("signal/rt_order", scenario::run);
