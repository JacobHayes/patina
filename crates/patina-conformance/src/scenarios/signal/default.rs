//! signal/default — default terminating actions are reported by wait status,
//! including WTERMSIG and the core-dump bit for core-action signals.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::Probe;
use crate::vehicle::fold_errno;
use libc::*;

fn child_signal(p: &Probe, sig: c_int) -> c_int {
    p.fork_child(
        || fold_errno(unsafe { fork() } as i64),
        || unsafe {
            signal(sig, SIG_DFL);
            kill(getpid(), sig);
            99
        },
    )
    .wait()
}

pub fn run(p: &Probe) {
    p.getpid();
    let term = child_signal(p, SIGTERM);
    p.rec
        .event("wait_status", 0)
        .arg("case", "SIGTERM")
        .field("signaled", WIFSIGNALED(term))
        .field("termsig", WTERMSIG(term))
        .field("core", WCOREDUMP(term))
        .emit();
    p.check(
        "SIGTERM terminates with no core flag",
        WIFSIGNALED(term) && WTERMSIG(term) == SIGTERM && !WCOREDUMP(term),
    );

    let core = child_signal(p, SIGABRT);
    p.rec
        .event("wait_status", 0)
        .arg("case", "SIGABRT")
        .field("signaled", WIFSIGNALED(core))
        .field("termsig", WTERMSIG(core))
        .field("core", WCOREDUMP(core))
        .emit();
    p.check(
        "SIGABRT terminates and sets the core flag",
        WIFSIGNALED(core) && WTERMSIG(core) == SIGABRT && WCOREDUMP(core),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/default",
    run,
    covers: &[Syscall::N_getpid],
    symbols: &["getpid"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "fork is a process-lifecycle trap (docs/arcs/syscall-conformance.md §7); the child oracle runs natively only",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: process spawn reached under patina: fork; the process class is a deterministic-runtime non-goal; failing closed",
        },
    }],
    ..DEFAULTS
};
