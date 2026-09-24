//! signal/queue — realtime signals queue in FIFO order with their payloads
//! (`rt_sigqueueinfo` SI_QUEUE, si_value), the thread's private pending
//! queue is dequeued before the process's shared one (kernel/signal.c
//! dequeue_signal), standard signals coalesce to one pending instance
//! (kernel/signal.c legacy_queue), a nonnegative si_code is
//! accepted when the target is the caller's own thread group (kernel/signal.c
//! do_rt_sigqueueinfo / do_rt_tgsigqueueinfo: EPERM only for another process),
//! and the errno vocabulary (ESRCH for a missing pid/tid, EINVAL past
//! SIGRTMAX).

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{Probe, neg};
use libc::*;

fn queued_info(pid: pid_t, uid: uid_t, sig: c_int, value: i32) -> siginfo_t {
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    info.si_signo = sig;
    info.si_code = SI_QUEUE;
    #[allow(deprecated)]
    {
        // The union starts at offset 16: _pad[0] is padding, then
        // si_pid, si_uid, si_value (the layout glibc's sigqueue fills).
        info._pad[1] = pid;
        info._pad[2] = uid as i32;
        info._pad[3] = value;
    }
    info
}

pub fn run(p: &Probe) {
    let pid = p.getpid() as pid_t;
    let tid = p.gettid() as pid_t;
    let uid = p.getuid() as uid_t;
    let rt = support::FIRST_RT;
    let rtset = support::one_set(rt);
    p.rt_sigprocmask(SIG_BLOCK, Some(&rtset), None, 8);
    let q1 = queued_info(pid, uid, rt, 11);
    let q2 = queued_info(pid, uid, rt, 22);
    let q3 = queued_info(pid, uid, rt, 33);
    p.check(
        "rt_sigqueueinfo realtime #1",
        p.rt_sigqueueinfo(pid, rt, &q1) == 0,
    );
    p.check(
        "rt_sigqueueinfo realtime #2",
        p.rt_sigqueueinfo(pid, rt, &q2) == 0,
    );
    p.check(
        "rt_tgsigqueueinfo realtime #3 to the calling thread",
        p.rt_tgsigqueueinfo(pid, tid, rt, &q3) == 0,
    );
    let mut a: siginfo_t = unsafe { std::mem::zeroed() };
    let mut b: siginfo_t = unsafe { std::mem::zeroed() };
    let mut c: siginfo_t = unsafe { std::mem::zeroed() };
    p.rt_sigtimedwait(&rtset, Some(&mut a), Some(0), 8);
    p.rt_sigtimedwait(&rtset, Some(&mut b), Some(0), 8);
    p.rt_sigtimedwait(&rtset, Some(&mut c), Some(0), 8);
    p.check(
        "three realtime instances of one number are all delivered",
        a.si_signo == rt && b.si_signo == rt && c.si_signo == rt,
    );
    p.check(
        "queued signals carry SI_QUEUE",
        a.si_code == SI_QUEUE && b.si_code == SI_QUEUE && c.si_code == SI_QUEUE,
    );
    let values = unsafe {
        [
            a.si_value().sival_ptr as usize as i32,
            b.si_value().sival_ptr as usize as i32,
            c.si_value().sival_ptr as usize as i32,
        ]
    };
    // kernel/signal.c dequeue_signal: the thread's private pending queue
    // (tgkill/rt_tgsigqueueinfo) is searched before the process's shared
    // one, so the thread-directed instance queued LAST is dequeued FIRST;
    // within the shared queue the instances stay FIFO.
    p.check("the thread-private queue is dequeued before the shared one; each queue is FIFO with its payloads", values == [33, 11, 22]);
    p.check(
        "the queue is empty afterwards",
        p.rt_sigtimedwait(&rtset, Some(&mut a), Some(0), 8) == neg(EAGAIN),
    );

    let stdset = support::one_set(SIGUSR1);
    p.rt_sigprocmask(SIG_BLOCK, Some(&stdset), None, 8);
    p.kill(pid, SIGUSR1);
    p.kill(pid, SIGUSR1);
    let mut si: siginfo_t = unsafe { std::mem::zeroed() };
    p.check(
        "one pending standard signal is dequeued",
        p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8) == SIGUSR1 as i64,
    );
    p.check(
        "standard signals coalesce",
        p.rt_sigtimedwait(&stdset, Some(&mut si), Some(0), 8) == neg(EAGAIN),
    );

    let mut forged: siginfo_t = unsafe { std::mem::zeroed() };
    forged.si_signo = rt;
    forged.si_code = SI_KERNEL;
    p.check(
        "rt_sigqueueinfo permits a nonnegative si_code to self",
        p.rt_sigqueueinfo(pid, rt, &forged) == 0,
    );
    p.check(
        "rt_tgsigqueueinfo permits a nonnegative si_code to self",
        p.rt_tgsigqueueinfo(pid, tid, rt, &forged) == 0,
    );
    p.rt_sigtimedwait(&rtset, Some(&mut si), Some(0), 8);
    p.rt_sigtimedwait(&rtset, Some(&mut si), Some(0), 8);
    forged.si_code = SI_QUEUE;
    p.check(
        "rt_tgsigqueueinfo rejects a dead tid",
        p.rt_tgsigqueueinfo(pid, 99999999, rt, &forged) == neg(ESRCH),
    );
    p.check(
        "rt_sigqueueinfo rejects a missing pid",
        p.rt_sigqueueinfo(99999999, rt, &forged) == neg(ESRCH),
    );
    let mut bad: siginfo_t = unsafe { std::mem::zeroed() };
    bad.si_signo = 65;
    bad.si_code = SI_QUEUE;
    p.check(
        "rt_sigqueueinfo past SIGRTMAX is EINVAL",
        p.rt_sigqueueinfo(pid, 65, &bad) == neg(EINVAL),
    );
    p.rt_sigprocmask(SIG_UNBLOCK, Some(&rtset), None, 8);
    p.rt_sigprocmask(SIG_UNBLOCK, Some(&stdset), None, 8);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/queue",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_getuid,
        Syscall::N_rt_sigprocmask,
        Syscall::N_kill,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_rt_sigqueueinfo,
        Syscall::N_rt_tgsigqueueinfo,
    ],
    symbols: &["getpid", "syscall", "getuid", "pthread_sigmask", "kill"],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(support::FIRST_RT),
            Generation::process(support::FIRST_RT),
            Generation::thread(support::FIRST_RT),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(support::FIRST_RT),
            Generation::thread(support::FIRST_RT),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
