//! signal/abort — glibc's `abort` (stdlib/abort.c): it unblocks SIGABRT
//! and raises it, so an installed handler runs even though the caller
//! blocked the signal; when the handler returns, abort restores `SIG_DFL`
//! and raises it again, and the process ends by SIGABRT.
//!
//! The handler records its run (the main thread is inside `abort`, holding
//! no recorder lock) and announces the death that follows its return, so
//! the death stays the stream's last event. A libc-only subject, so the
//! libc vehicle alone.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::Probe;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::signals as support;

static PROBE: AtomicPtr<Probe> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn on_abort(sig: c_int) {
    // SAFETY: `run` stored its probe, which outlives the process.
    let p = unsafe { &*PROBE.load(Ordering::SeqCst) };
    p.rec.event("handler", 0).arg("sig", sig).emit();
    p.dies_by(SIGABRT);
}

pub fn run(p: &Probe) {
    PROBE.store((p as *const Probe).cast_mut(), Ordering::SeqCst);
    support::install_with(SIGABRT, 0, on_abort as extern "C" fn(c_int) as usize);
    let blocked = support::one_set(SIGABRT);
    // SAFETY: a valid set.
    let result = unsafe { sigprocmask(SIG_BLOCK, &blocked, std::ptr::null_mut()) };
    p.require("block SIGABRT", result == 0);
    p.rec.event("abort", 0).emit();
    // SAFETY: ends the process.
    unsafe { abort() }
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/abort",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_rt_sigaction,
        Syscall::N_rt_sigprocmask,
        Syscall::N_tgkill,
    ],
    symbols: &["sigaction", "sigprocmask", "abort"],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: &[Vehicle::Libc],
        what: "the shim's abort (c/posix/signal_process.c → patina_abort) finalizes the trace, shuts the runtime down and calls the host's abort: SIGABRT never passes the virtual kernel, so the guest's handler never runs, and the run ends by the host signal (its result classified infra). The pin is the runner's marker for a SIGABRT death with a complete trace (cargo-patina lib.rs append_native_infra_marker; the newline ends it before any `trace=incomplete`), which rules out a shim fatal (those abort without finalizing), but not another guest-side path to the same death before the handler records: patina prints nothing of its own on this path, and this stack does not change patina",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(SIGABRT),
            diagnostic: "PATINA_INFRA native_run signal=6\n",
        },
    }],
    ..DEFAULTS
};
