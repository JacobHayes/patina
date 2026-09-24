//! signal/block — the waits that park until a signal exists must not return
//! before one does: `pause` returns `EINTR` only after a handled signal ran
//! (kernel/signal.c: pause → -ERESTARTNOHAND → EINTR under a handler), a
//! `rt_sigtimedwait` with no timeout parks until a matching signal is
//! generated, a handled signal outside its set interrupts it with `EINTR`
//! after the handler, and a blocking `signalfd` read parks until a matching
//! signal is pending (fs/signalfd.c signalfd_dequeue: schedule() until
//! next_signal). Each helper marks the stream (`helper_kill`) immediately
//! before it kills, so a wait that returned early shows up as the wait's
//! event preceding the mark, and the handler count at return is checked.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};

use crate::signals as support;

use crate::observe::Norm;
use crate::probe::{Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::mem::size_of;
use std::thread;

fn delayed_kill<'a>(scope: &'a thread::Scope<'a, '_>, p: &'a Probe, pid: pid_t, sig: c_int) {
    let main_tid = support::gettid();
    scope.spawn(move || {
        support::until_parked(main_tid);
        p.mark("helper_kill", &[("sig", Value::from(sig))]);
        unsafe {
            kill(pid, sig);
        }
    });
}

pub fn run(p: &Probe) {
    support::reset();
    let pid = p.getpid() as pid_t;
    support::install(SIGUSR1, 0, false);

    thread::scope(|scope| {
        delayed_kill(scope, p, pid, SIGUSR1);
        p.check(
            "pause returns EINTR once a handled signal was delivered",
            p.pause() == neg(EINTR),
        );
    });
    p.check(
        "the handler ran before pause returned",
        support::count() == 1,
    );

    let usr2 = support::one_set(SIGUSR2);
    p.check(
        "block SIGUSR2",
        p.rt_sigprocmask(SIG_BLOCK, Some(&usr2), None, 8) == 0,
    );
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    thread::scope(|scope| {
        delayed_kill(scope, p, pid, SIGUSR2);
        p.check(
            "rt_sigtimedwait without a timeout parks until the helper's signal",
            p.rt_sigtimedwait(&usr2, Some(&mut info), None, 8) == SIGUSR2 as i64,
        );
    });
    p.check(
        "it reports the sender code SI_USER",
        info.si_code == SI_USER,
    );
    p.check(
        "no handler ran for the dequeued signal",
        support::count() == 1,
    );

    thread::scope(|scope| {
        delayed_kill(scope, p, pid, SIGUSR1);
        p.check(
            "a handled signal outside the set interrupts rt_sigtimedwait with EINTR",
            p.rt_sigtimedwait(&usr2, Some(&mut info), None, 8) == neg(EINTR),
        );
    });
    p.check(
        "that handler ran before the wait returned",
        support::count() == 2,
    );

    let sfd = p.signalfd4(-1, &usr2, 0);
    p.require("blocking signalfd", sfd >= 0);
    let mut ssi: signalfd_siginfo = unsafe { std::mem::zeroed() };
    thread::scope(|scope| {
        delayed_kill(scope, p, pid, SIGUSR2);
        let n = p.call_unrecorded(
            Syscall::N_read,
            [
                sfd as i64,
                &mut ssi as *mut signalfd_siginfo as i64,
                size_of::<signalfd_siginfo>() as i64,
                0,
                0,
                0,
            ],
        );
        p.rec
            .event("read", n)
            .arg("fd", sfd)
            .norm("args.fd", Norm::Relative("fd"))
            .arg("len", size_of::<signalfd_siginfo>())
            .emit();
        p.check(
            "a blocking signalfd read parks until a matching signal is pending",
            n == size_of::<signalfd_siginfo>() as i64,
        );
    });
    p.check(
        "the read dequeued the helper's signal",
        ssi.ssi_signo == SIGUSR2 as u32 && ssi.ssi_code == SI_USER,
    );
    p.check(
        "no handler ran for the signalfd-dequeued signal",
        support::count() == 2,
    );
    p.close(sfd);
    p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr2), None, 8);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/block",
    run,
    covers: &[
        Syscall::N_getpid,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_pause,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_signalfd4,
        Syscall::N_read,
        Syscall::N_close,
        Syscall::N_kill,
    ],
    symbols: &[
        "getpid",
        "pause",
        "read",
        "close",
        "kill",
        "sigaction",
        "syscall",
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR2),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
