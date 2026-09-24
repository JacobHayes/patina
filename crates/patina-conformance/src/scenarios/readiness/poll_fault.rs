//! readiness/poll_fault — poll(2) over descriptor arrays the kernel cannot
//! use (fs/select.c `do_sys_poll`): more entries than `RLIMIT_NOFILE` is
//! `EINVAL`, judged before the array is read, and an unreadable array is
//! `EFAULT`. Its own scenario, because a door that reads the array first
//! ends the whole run (and a crash loses the captured event stream).
//!
//! The generic (arm64) table has no `poll` row: there every vehicle issues
//! `ppoll` (a shape glibc's wrapper cannot pass a bad array through).

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
#[cfg(target_arch = "x86_64")]
use crate::compare::Ending;
use crate::compare::Failure;
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
#[cfg(not(target_arch = "x86_64"))]
use std::time::Duration;

pub fn run(p: &Probe) {
    // The limit the check is about, as this process has it (the harness
    // pins it; the check does not repeat the number).
    let mut limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: an out-pointer to a local rlimit.
    let r = unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) };
    p.mark(
        "rlimit_nofile",
        &[
            ("ret", serde_json::Value::from(r)),
            ("soft", serde_json::Value::from(limit.rlim_cur)),
        ],
    );
    p.require("getrlimit(RLIMIT_NOFILE)", r == 0);
    p.check(
        "more descriptors than RLIMIT_NOFILE is EINVAL, before the array is read",
        p.poll_fault(limit.rlim_cur as usize + 1) == neg(EINVAL),
    );
    p.check(
        "an unreadable array is EFAULT",
        p.poll_fault(1) == neg(EFAULT),
    );
}

/// When the harness starts confirming the arm64 hang: a completed patina run
/// of a scenario this size takes about 0.5 s on the arm64 VM (measured:
/// readiness/ppoll 0.51 s, readiness/poll 0.48 s), and a leg that is merely
/// slow is never confirmed (the harness needs the started journal and a
/// whole second without a change), so a small bound only saves time.
#[cfg(not(target_arch = "x86_64"))]
const HANG_WITHIN: Duration = Duration::from_secs(2);

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/poll_fault",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_poll,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_ppoll,
    ],
    symbols: &["poll"],
    gaps: &[
        #[cfg(target_arch = "x86_64")]
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "poll over an unreadable array is a SIGSEGV instead of EFAULT: patina_poll (thread/readiness.rs `poll`) reads the array without judging the pointer (it does judge RLIMIT_NOFILE first: the arm64 leg's journal shows that call answering EINVAL), and on x86_64 the containment SIGSEGV handler ends the run, losing the captured event stream",
            failure: Failure::Stops {
                events: 0,
                ending: Ending::Signal(libc::SIGSEGV),
                diagnostic: "native_run signal=11",
            },
        },
        #[cfg(not(target_arch = "x86_64"))]
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "ppoll over an unreadable array never returns (more entries than RLIMIT_NOFILE is EINVAL as the kernel answers, event 1): patina_poll (thread/readiness.rs `poll`) reads the array without judging the pointer and faults; with no containment SIGSEGV handler armed on arm64 the fault reaches Rust std's own handler (stack_overflow::signal_handler), whose sigaction call re-enters the shim (patina_signal_action_libc → patina_signal_action) and spins there for good — observed on the arm64 VM: the guest at one PC in patina_signal_action, 100% user time, no system time, no voluntary context switch, frame chain signal_handler ← readiness::poll ← patina_poll ← the ppoll SUD row (ptrace GETREGSET and a frame-pointer walk). The kernel answers EFAULT at once",
            failure: Failure::Hangs {
                events: 3,
                within: HANG_WITHIN,
            },
        },
    ],
    ..DEFAULTS
};
