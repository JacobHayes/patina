//! signal/handler_flags — what a handler's `sa_flags` change about its
//! delivery (kernel/signal.c handle_signal, signal_setup_done, get_signal):
//!
//! * by default the signal being handled is blocked for the handler's
//!   extent, so a same-signal raise inside the handler is delivered after it
//!   returns (two runs, never nested);
//! * `SA_NODEFER` leaves it unblocked, so the raise nests (depth 2);
//! * `SA_RESETHAND` restores `SIG_DFL` before the handler runs (`SA_ONESHOT`
//!   clears the handler), as libc and the raw door both report, so the first
//!   signal is handled once and the second ends the process by that signal
//!   (the `__termination` line).

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::Probe;
use libc::*;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

static DEPTH: AtomicI32 = AtomicI32::new(0);
static MAX_DEPTH: AtomicI32 = AtomicI32::new(0);
static RUNS: AtomicUsize = AtomicUsize::new(0);

/// Raises its own signal again on its first run, and records how deeply
/// its runs nested.
extern "C" fn raises_same(sig: c_int) {
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    MAX_DEPTH.fetch_max(depth, Ordering::SeqCst);
    if RUNS.fetch_add(1, Ordering::SeqCst) == 0 {
        unsafe {
            kill(getpid(), sig);
        }
    }
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}

/// Install `raises_same` for SIGUSR1 with `flags`, raise it, and answer
/// (runs, deepest nesting).
fn raise_within_handler(p: &Probe, pid: pid_t, flags: c_int) -> (usize, i32) {
    DEPTH.store(0, Ordering::SeqCst);
    MAX_DEPTH.store(0, Ordering::SeqCst);
    RUNS.store(0, Ordering::SeqCst);
    support::install_with(SIGUSR1, flags, raises_same as extern "C" fn(c_int) as usize);
    p.kill(pid, SIGUSR1);
    (
        RUNS.load(Ordering::SeqCst),
        MAX_DEPTH.load(Ordering::SeqCst),
    )
}

pub fn run(p: &Probe) {
    let pid = p.getpid() as pid_t;
    p.check(
        "by default the handled signal is deferred: a raise inside the handler runs after it",
        raise_within_handler(p, pid, 0) == (2, 1),
    );
    p.check(
        "SA_NODEFER lets the same signal nest",
        raise_within_handler(p, pid, SA_NODEFER) == (2, 2),
    );

    support::reset();
    support::install(SIGUSR2, SA_RESETHAND, false);
    p.check(
        "kill(self, SIGUSR2) with SA_RESETHAND",
        p.kill(pid, SIGUSR2) == 0,
    );
    p.check("the handler ran once", support::count() == 1);
    p.check(
        "SA_RESETHAND restored SIG_DFL",
        support::disposition(SIGUSR2) == "SIG_DFL",
    );
    let (r, raw) = p.rt_sigaction_query(SIGUSR2);
    p.check(
        "the raw door reports SIG_DFL too",
        r == 0 && raw.handler == 0,
    );
    p.dies_by(SIGUSR2);
    p.kill(pid, SIGUSR2);
    p.check("unreachable: the second SIGUSR2 returned", false);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/handler_flags",
    run,
    covers: &[Syscall::N_getpid, Syscall::N_kill, Syscall::N_rt_sigaction],
    symbols: &["getpid", "kill", "sigaction", "syscall"],
    trace: Some(TraceFacts {
        // Each deferral case's kill and its handler's raise, then the
        // SA_RESETHAND pair.
        generations: &[
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR1),
            Generation::process(SIGUSR2),
            Generation::process(SIGUSR2),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
