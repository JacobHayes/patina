//! signal/queue — queued signal payloads, rt_sigqueueinfo/tgsigqueueinfo error
//! rules, and standard-signal coalescing versus realtime queuing.

#[cfg(target_os = "linux")]
mod scenario {
    #[path = "support.rs"]
    mod support;

    use libc::*;
    use syscall_conformance::calls::{neg, Probe};

    fn queued_info(pid: pid_t, uid: uid_t, sig: c_int, value: i32) -> siginfo_t {
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        info.si_signo = sig;
        info.si_code = SI_QUEUE;
        #[allow(deprecated)]
        {
            info._pad[0] = pid;
            info._pad[1] = uid as i32;
            info._pad[2] = value;
        }
        info
    }

    pub fn run(p: &Probe) {
        let pid = p.getpid() as pid_t;
        let tid = p.gettid() as pid_t;
        let uid = p.getuid() as uid_t;
        let rt = 34;
        let rtset = support::one_set(rt);
        p.rt_sigprocmask(SIG_BLOCK, Some(&rtset), None, 8);
        let q1 = queued_info(pid, uid, rt, 11);
        let q2 = queued_info(pid, uid, rt, 22);
        p.check("rt_sigqueueinfo realtime #1", p.rt_sigqueueinfo(pid, rt, &q1) == 0);
        p.check("rt_sigqueueinfo realtime #2", p.rt_sigqueueinfo(pid, rt, &q2) == 0);
        let mut a: siginfo_t = unsafe { std::mem::zeroed() };
        let mut b: siginfo_t = unsafe { std::mem::zeroed() };
        p.rt_sigtimedwait(&rtset, Some(&mut a), Some(0), 8);
        p.rt_sigtimedwait(&rtset, Some(&mut b), Some(0), 8);
        p.check("two realtime signals with one number are both delivered", a.si_signo == rt && b.si_signo == rt);
        p.check("queued signal carries SI_QUEUE", a.si_code == SI_QUEUE && b.si_code == SI_QUEUE);

        let stdset = support::one_set(SIGUSR1);
        p.rt_sigprocmask(SIG_BLOCK, Some(&stdset), None, 8);
        p.kill(pid, SIGUSR1);
        p.kill(pid, SIGUSR1);
        let mut si: siginfo_t = unsafe { std::mem::zeroed() };
        p.check("one pending standard signal is dequeued", p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8) == SIGUSR1 as i64);
        p.check("standard signals coalesce", p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8) == neg(EAGAIN));

        let mut forged: siginfo_t = unsafe { std::mem::zeroed() };
        forged.si_signo = rt;
        forged.si_code = SI_KERNEL;
        p.check("rt_sigqueueinfo permits a nonnegative si_code to self", p.rt_sigqueueinfo(pid, rt, &forged) == 0);
        p.check("rt_tgsigqueueinfo permits a nonnegative si_code to self", p.rt_tgsigqueueinfo(pid, tid, rt, &forged) == 0);
        p.rt_sigtimedwait(&rtset, Some(&mut si), Some(0), 8);
        p.rt_sigtimedwait(&rtset, Some(&mut si), Some(0), 8);
        forged.si_code = SI_QUEUE;
        p.check("rt_tgsigqueueinfo rejects a dead tid", p.rt_tgsigqueueinfo(pid, 99999999, rt, &forged) == neg(ESRCH));
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&rtset), None, 8);
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&stdset), None, 8);
    }
}

syscall_conformance::probe_main!("signal/queue", scenario::run);
