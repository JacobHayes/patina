//! signal/restart — `restart_syscall` with no restart pending
//! (kernel/signal.c `sys_restart_syscall`): the kernel issues it itself
//! when a signal without a handler interrupts a sleep it can resume
//! (`-ERESTART_RESTARTBLOCK`). A fresh task's restart block holds
//! `do_no_restart_syscall`, and `rt_sigreturn` resets it to that, so here —
//! before any interrupted sleep, and after a handler has returned — a
//! caller that issues it finds nothing to restart and gets `EINTR`,
//! whatever it passes. (A sleep restarted after a stop keeps its restart
//! function until the next sigreturn; the scenario never stops.)
//!
//! glibc wraps no `restart_syscall`, so the scenario runs through the
//! kernel vehicles.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::signals as support;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

fn restart(p: &Probe, args: [i64; 6], what: &str) -> i64 {
    p.observed(Syscall::N_restart_syscall, args, &[("args", what.into())])
}

pub fn run(p: &Probe) {
    p.check(
        "restart_syscall with nothing to restart is EINTR",
        restart(p, [0; 6], "zero") == neg(EINTR),
    );
    p.check(
        "whatever the caller passes",
        restart(p, [1, 2, 3, 4, 5, 6], "arbitrary") == neg(EINTR),
    );
    support::reset();
    support::install(SIGUSR1, 0, false);
    let (pid, tid) = (p.getpid() as pid_t, p.gettid() as pid_t);
    p.check(
        "a handled SIGUSR1 runs",
        p.tgkill(pid, tid, SIGUSR1) == 0 && support::count() == 1,
    );
    p.check(
        "after a handler's rt_sigreturn there is still nothing to restart",
        restart(p, [0; 6], "zero") == neg(EINTR),
    );
    support::install_disposition(SIGUSR1, SIG_DFL);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/restart",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_restart_syscall],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::KERNEL,
        what: "restart_syscall is a Trap(signal-abi) in the registry, so the SUD dispatcher aborts at the row. Patina restarts an interrupted wait where it resumes, so a guest never has a restart pending, and the faithful answer the model owes is do_no_restart_syscall's: EINTR, whatever the arguments",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall restart_syscall (nr",
        },
    }],
    ..DEFAULTS
};
