//! signal/rt_order — dequeue order (kernel/signal.c next_signal: the
//! lowest-numbered pending signal first, so every standard signal precedes
//! every realtime one and SIGRTMIN precedes SIGRTMIN+1; within one realtime
//! number the instances are FIFO with their payloads).

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::Probe;
use libc::*;

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

    let rt = support::FIRST_RT;
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
    let all = support::set_of(&[SIGUSR1, SIGUSR2, support::FIRST_RT, support::SECOND_RT]);
    p.rt_sigprocmask(SIG_BLOCK, Some(&all), None, 8);
    let h = queued_info(pid, support::SECOND_RT, 7);
    p.rt_sigqueueinfo(pid, support::SECOND_RT, &h);
    let l1 = queued_info(pid, support::FIRST_RT, 8);
    let l2 = queued_info(pid, support::FIRST_RT, 9);
    p.rt_sigqueueinfo(pid, support::FIRST_RT, &l1);
    p.rt_sigqueueinfo(pid, support::FIRST_RT, &l2);
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
        order
            == vec![
                SIGUSR1 as i64,
                SIGUSR2 as i64,
                i64::from(support::FIRST_RT),
                i64::from(support::FIRST_RT),
                i64::from(support::SECOND_RT),
            ],
    );
    p.check(
        "the realtime payloads follow the same order",
        payloads == vec![0, 0, 8, 9, 7],
    );
    p.rt_sigprocmask(SIG_UNBLOCK, Some(&all), None, 8);
    p.rt_sigprocmask(SIG_UNBLOCK, Some(&stdset), None, 8);
    p.rt_sigprocmask(SIG_UNBLOCK, Some(&rtset), None, 8);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/rt_order",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_rt_sigprocmask,
        Syscall::N_kill,
        Syscall::N_rt_sigtimedwait,
    ],
    symbols: &["getpid", "pthread_sigmask", "kill"],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
            Generation::process(support::FIRST_RT),
            Generation::process(support::FIRST_RT),
            Generation::process(support::SECOND_RT),
            Generation::process(support::FIRST_RT),
            Generation::process(support::FIRST_RT),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
