//! signal/rt_order — dequeue order (kernel/signal.c next_signal: the
//! lowest-numbered pending signal first, so every standard signal precedes
//! every realtime one and SIGRTMIN precedes SIGRTMIN+1; within one realtime
//! number the instances are FIFO with their payloads).

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use syscall_conformance::calls::Probe;

    fn queued_info(pid: pid_t, sig: c_int, value: i32) -> siginfo_t {
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        info.si_signo = sig;
        info.si_code = SI_QUEUE;
        #[allow(deprecated)]
        {
            // The union starts at offset 16: _pad[0] is padding, then
            // si_pid, si_uid, si_value (the layout glibc's sigqueue fills).
            info._pad[1] = pid;
            info._pad[2] = unsafe { getuid() as i32 };
            info._pad[3] = value;
        }
        info
    }

    pub fn run(p: &Probe) {
        let pid = p.getpid() as pid_t;
        let mut stdset = support::empty_set();
        unsafe {
            sigaddset(&mut stdset, SIGUSR1);
            sigaddset(&mut stdset, SIGUSR2);
        }
        p.rt_sigprocmask(SIG_BLOCK, Some(&stdset), None, 8);
        p.kill(pid, SIGUSR2);
        p.kill(pid, SIGUSR1);
        let mut si: siginfo_t = unsafe { std::mem::zeroed() };
        let first = p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8);
        let second = p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8);
        p.check(
            "lower-numbered pending standard signal wins",
            first == SIGUSR1 as i64 && second == SIGUSR2 as i64,
        );

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
        p.check(
            "same-number realtime signals are both delivered",
            a.si_signo == rt && b.si_signo == rt,
        );
        let values = unsafe {
            [
                a.si_value().sival_ptr as usize as i32,
                b.si_value().sival_ptr as usize as i32,
            ]
        };
        p.check(
            "same-number realtime signals dequeue FIFO",
            values == [1, 2],
        );

        // A mixed pending set: 35, 34 (two instances), SIGUSR2, SIGUSR1,
        // generated in that order, dequeues as USR1, USR2, 34, 34, 35.
        let all = support::set_of(&[SIGUSR1, SIGUSR2, 34, 35]);
        p.rt_sigprocmask(SIG_BLOCK, Some(&all), None, 8);
        let h = queued_info(pid, 35, 7);
        p.rt_sigqueueinfo(pid, 35, &h);
        let l1 = queued_info(pid, 34, 8);
        let l2 = queued_info(pid, 34, 9);
        p.rt_sigqueueinfo(pid, 34, &l1);
        p.rt_sigqueueinfo(pid, 34, &l2);
        p.kill(pid, SIGUSR2);
        p.kill(pid, SIGUSR1);
        let mut order = Vec::new();
        let mut payloads = Vec::new();
        for _ in 0..5 {
            let mut info: siginfo_t = unsafe { std::mem::zeroed() };
            order.push(p.rt_sigtimedwait(&all, Some(&mut info), Some(0), 8));
            payloads.push(if info.si_code == SI_QUEUE {
                unsafe { info.si_value().sival_ptr as usize as i32 }
            } else {
                0
            });
        }
        p.check(
            "standard signals before realtime, lowest number first, FIFO within a number",
            order == vec![SIGUSR1 as i64, SIGUSR2 as i64, 34, 34, 35],
        );
        p.check(
            "the realtime payloads follow the same order",
            payloads == vec![0, 0, 8, 9, 7],
        );
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&all), None, 8);
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&stdset), None, 8);
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&rtset), None, 8);
    }
}

syscall_conformance::probe_main!("signal/rt_order", scenario::run);
