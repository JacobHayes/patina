//! signal/queue — how the pending set is dequeued (kernel/signal.c):
//!
//! * a realtime signal queues every instance with its payload
//!   (`rt_sigqueueinfo`/`rt_tgsigqueueinfo`: `SI_QUEUE`, `si_value`); a
//!   standard one coalesces to one pending instance (legacy_queue);
//! * dequeue_signal searches the thread's private pending queue before the
//!   process's shared one; within a queue next_signal takes the
//!   lowest-numbered signal first, so every standard signal precedes every
//!   realtime one, and one realtime number's instances come FIFO;
//! * a nonnegative `si_code` is accepted when the target is the caller's own
//!   thread group (do_rt_sigqueueinfo / do_rt_tgsigqueueinfo: `EPERM` only
//!   for another process), and the errno vocabulary (`ESRCH` for a missing
//!   pid/tid, `EINVAL` past SIGRTMAX).
//!
//! Each case generates its signals while all four numbers are blocked, then
//! dequeues them with zero-timeout `rt_sigtimedwait`s until `EAGAIN`.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::signals::{self as support, FIRST_RT, SECOND_RT, queued_info};

use crate::probe::{Probe, neg};
use libc::*;

/// How a case generates one signal.
enum Send {
    /// `kill(pid, sig)`: process-directed, `SI_USER`.
    Kill(c_int),
    /// `rt_sigqueueinfo(pid, sig, …)` with a payload: process-directed.
    Queue(c_int, i32),
    /// `rt_tgsigqueueinfo(pid, tid, sig, …)` with a payload: to this thread.
    ToThread(c_int, i32),
}

struct Case {
    what: &'static str,
    send: &'static [Send],
    /// `(signal, payload)` in dequeue order; a `kill` carries payload 0,
    /// and no queued instance does.
    dequeued: &'static [(c_int, i32)],
}

const CASES: &[Case] = &[
    Case {
        what: "the thread's private queue is dequeued before the shared one; each queue is FIFO with its payloads",
        send: &[
            Send::Queue(FIRST_RT, 11),
            Send::Queue(FIRST_RT, 22),
            Send::ToThread(FIRST_RT, 33),
        ],
        dequeued: &[(FIRST_RT, 33), (FIRST_RT, 11), (FIRST_RT, 22)],
    },
    Case {
        what: "a standard signal coalesces to one pending instance",
        send: &[Send::Kill(SIGUSR1), Send::Kill(SIGUSR1)],
        dequeued: &[(SIGUSR1, 0)],
    },
    Case {
        what: "standard signals before realtime, lowest number first, FIFO within a number",
        send: &[
            Send::Queue(SECOND_RT, 7),
            Send::Queue(FIRST_RT, 8),
            Send::Queue(FIRST_RT, 9),
            Send::Kill(SIGUSR2),
            Send::Kill(SIGUSR1),
        ],
        dequeued: &[
            (SIGUSR1, 0),
            (SIGUSR2, 0),
            (FIRST_RT, 8),
            (FIRST_RT, 9),
            (SECOND_RT, 7),
        ],
    },
];

pub fn run(p: &Probe) {
    let pid = p.getpid() as pid_t;
    let tid = p.gettid() as pid_t;
    let uid = p.getuid() as uid_t;
    let all = support::set_of(&[SIGUSR1, SIGUSR2, FIRST_RT, SECOND_RT]);
    p.check(
        "block SIGUSR1, SIGUSR2 and two realtime signals",
        p.rt_sigprocmask(SIG_BLOCK, Some(&all), None, 8) == 0,
    );

    for case in CASES {
        let sent = case.send.iter().all(|send| {
            let r = match *send {
                Send::Kill(sig) => p.kill(pid, sig),
                Send::Queue(sig, value) => {
                    p.rt_sigqueueinfo(pid, sig, &queued_info(pid, uid, sig, value))
                }
                Send::ToThread(sig, value) => {
                    p.rt_tgsigqueueinfo(pid, tid, sig, &queued_info(pid, uid, sig, value))
                }
            };
            r == 0
        });
        p.check(&format!("{}: every signal is generated", case.what), sent);
        let mut dequeued = Vec::new();
        let mut codes = Vec::new();
        for _ in case.dequeued {
            // SAFETY: all-zero is a valid siginfo_t.
            let mut info: siginfo_t = unsafe { std::mem::zeroed() };
            let sig = p.rt_sigtimedwait(&all, Some(&mut info), Some(0), 8);
            let payload = if info.si_code == SI_QUEUE {
                unsafe { info.si_value().sival_ptr as usize as i32 }
            } else {
                0
            };
            dequeued.push((sig as c_int, payload));
            codes.push(info.si_code);
        }
        p.check(case.what, dequeued == case.dequeued);
        let queued_or_killed = case
            .dequeued
            .iter()
            .map(|&(_, payload)| if payload == 0 { SI_USER } else { SI_QUEUE });
        p.check(
            &format!(
                "{}: queued instances carry SI_QUEUE, kills SI_USER",
                case.what
            ),
            codes.into_iter().eq(queued_or_killed),
        );
        p.check(
            &format!("{}: nothing more is pending", case.what),
            p.rt_sigtimedwait(&all, None, Some(0), 8) == neg(EAGAIN),
        );
    }

    let rt = FIRST_RT;
    let rtset = support::one_set(rt);
    let mut si: siginfo_t = unsafe { std::mem::zeroed() };
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
    p.rt_sigprocmask(SIG_UNBLOCK, Some(&all), None, 8);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/queue",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
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
    trace: Some(TraceFacts {
        // CASES in order, then the two forged-code sends.
        generations: &[
            Generation::process(FIRST_RT),
            Generation::process(FIRST_RT),
            Generation::thread(FIRST_RT),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SECOND_RT),
            Generation::process(FIRST_RT),
            Generation::process(FIRST_RT),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
            Generation::process(FIRST_RT),
            Generation::thread(FIRST_RT),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
