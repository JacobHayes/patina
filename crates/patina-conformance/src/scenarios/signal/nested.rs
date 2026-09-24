//! signal/nested — handler mask semantics (the signal being handled is
//! blocked for the handler's extent unless `SA_NODEFER`, so a same-signal
//! raise inside the handler is delivered after it returns), `SA_NODEFER`
//! recursion, `SA_RESETHAND` observed by the child oracle's termination
//! (kept natively; under patina `fork` is a process-lifecycle trap by design,
//! and `signal/resethand_term` pins the same fact in-process), and a raw
//! `rt_sigaction` without `SA_RESTORER`, which the kernel accepts at
//! registration (the restorer matters at frame setup, arch/x86/kernel/
//! signal.c).

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::Probe;
use crate::vehicle::fold_errno;
use libc::*;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

static DEPTH: AtomicI32 = AtomicI32::new(0);
static MAX_DEPTH: AtomicI32 = AtomicI32::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn raises_same(sig: c_int) {
    let d = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    MAX_DEPTH.fetch_max(d, Ordering::SeqCst);
    if COUNT.fetch_add(1, Ordering::SeqCst) == 0 {
        unsafe {
            kill(getpid(), sig);
        }
    }
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}

fn install(sig: c_int, flags: c_int) {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = flags;
        sa.sa_sigaction = raises_same as *const () as usize;
        assert_eq!(sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

fn reset() {
    DEPTH.store(0, Ordering::SeqCst);
    MAX_DEPTH.store(0, Ordering::SeqCst);
    COUNT.store(0, Ordering::SeqCst);
}

fn reset_hand_status(p: &Probe) -> c_int {
    p.fork_child(
        || fold_errno(unsafe { fork() } as i64),
        || unsafe {
            install(SIGUSR2, SA_RESETHAND);
            kill(getpid(), SIGUSR2);
            kill(getpid(), SIGUSR2);
            99
        },
    )
    .wait()
}

pub fn run(p: &Probe) {
    reset();
    install(SIGUSR1, 0);
    p.kill(p.getpid() as pid_t, SIGUSR1);
    p.check(
        "default handler mask defers same signal",
        COUNT.load(Ordering::SeqCst) == 2 && MAX_DEPTH.load(Ordering::SeqCst) == 1,
    );

    reset();
    install(SIGUSR1, SA_NODEFER);
    p.kill(p.getpid() as pid_t, SIGUSR1);
    p.check(
        "SA_NODEFER permits nested same-signal delivery",
        COUNT.load(Ordering::SeqCst) == 2 && MAX_DEPTH.load(Ordering::SeqCst) == 2,
    );

    let status = reset_hand_status(p);
    p.rec
        .event("wait_status", 0)
        .arg("case", "SA_RESETHAND")
        .field("signaled", WIFSIGNALED(status))
        .field("termsig", WTERMSIG(status))
        .emit();
    p.check(
        "SA_RESETHAND resets disposition before the second raise",
        WIFSIGNALED(status) && WTERMSIG(status) == SIGUSR2,
    );
    let mut bad: sigaction = unsafe { std::mem::zeroed() };
    bad.sa_sigaction = raises_same as *const () as usize;
    unsafe {
        sigemptyset(&mut bad.sa_mask);
    }
    bad.sa_flags = 0;
    p.check(
        "raw rt_sigaction without SA_RESTORER is accepted at registration time",
        p.call_observed(
            Syscall::N_rt_sigaction,
            [SIGUSR1 as i64, &bad as *const sigaction as i64, 0, 8, 0, 0],
        ) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/nested",
    run,
    covers: &[Syscall::N_getpid, Syscall::N_kill, Syscall::N_rt_sigaction],
    symbols: &["getpid", "kill", "sigaction"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "fork is a process-lifecycle trap (docs/arcs/syscall-conformance.md §7); the child oracle runs natively only",
        failure: Failure::Stops {
            events: 6,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: process spawn reached under patina: fork; the process class is a deterministic-runtime non-goal; failing closed",
        },
    }],
    ..DEFAULTS
};
