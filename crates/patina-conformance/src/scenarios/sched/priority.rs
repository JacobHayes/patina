//! sched/priority — nice values through `getpriority`/`setpriority`
//! (kernel/sys.c):
//!
//! * the raw row answers `20 - nice` (glibc's wrapper converts it back): a
//!   process starts at nice 0, answering 20 for pid 0, its own pid, and its
//!   process group (it leads its own, alone);
//! * a pid or group no process has is `ESRCH`, and so is a user with no
//!   process; an unknown `which` is `EINVAL`, to either row;
//! * lowering the priority (raising nice) is always allowed, clamped to 19;
//!   with `RLIMIT_NICE` at 0 (lowered here; lowering is always allowed)
//!   raising it again is `EACCES`.
//!
//! The native run must start at nice 0, as the virtual kernel's process
//! does (`Need::NiceZero`): a harness that runs its tests niced cannot give
//! the priority back, so such a host reports the scenario not run.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, Who, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;
    p.check(
        "a process starts at nice 0 (the row answers 20)",
        p.getpriority(PRIO_PROCESS as i32, Who::Caller) == 20,
    );
    p.check(
        "its own pid answers the same",
        p.getpriority(PRIO_PROCESS as i32, Who::Own(pid)) == 20,
    );
    p.check(
        "so does its process group",
        p.getpriority(PRIO_PGRP as i32, Who::Caller) == 20,
    );
    p.check(
        "a pid no process has is ESRCH",
        p.getpriority(PRIO_PROCESS as i32, Who::Missing) == neg(ESRCH),
    );
    p.check(
        "a group no process is in is ESRCH",
        p.getpriority(PRIO_PGRP as i32, Who::Missing) == neg(ESRCH),
    );
    p.check(
        "a user with no process is ESRCH",
        p.getpriority(PRIO_USER as i32, Who::Missing) == neg(ESRCH),
    );
    p.check(
        "an unknown which is EINVAL",
        p.getpriority(3, Who::Caller) == neg(EINVAL),
    );

    p.check(
        "lowering the priority is allowed",
        p.setpriority(PRIO_PROCESS as i32, Who::Caller, 1) == 0,
    );
    p.check(
        "and reads back",
        p.getpriority(PRIO_PROCESS as i32, Who::Caller) == 19,
    );
    p.check(
        "a nice past 19 is clamped",
        p.setpriority(PRIO_PROCESS as i32, Who::Own(pid), 25) == 0,
    );
    p.check(
        "to 19",
        p.getpriority(PRIO_PROCESS as i32, Who::Caller) == 1,
    );
    p.check(
        "setpriority of a pid no process has is ESRCH",
        p.setpriority(PRIO_PROCESS as i32, Who::Missing, 19) == neg(ESRCH),
    );
    p.check(
        "setpriority of an unknown which is EINVAL",
        p.setpriority(3, Who::Caller, 19) == neg(EINVAL),
    );
    p.check(
        "RLIMIT_NICE lowers to 0",
        p.setrlimit(RLIMIT_NICE as i32, 0, 0) == 0,
    );
    p.check(
        "then raising the priority is EACCES",
        p.setpriority(PRIO_PROCESS as i32, Who::Caller, 18) == neg(EACCES),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sched/priority",
    run,
    covers: &[Syscall::N_getpriority, Syscall::N_setpriority],
    symbols: &["syscall", "getpid", "setrlimit"],
    needs: &[Need::Unprivileged, Need::NiceZero],
    gaps: &[Gap {
        status: Status::Pending(Arc::TimeTimersSchedIdentity),
        vehicles: Vehicle::ALL,
        what: "getpriority is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door (its libc spelling is syscall(2): the shim defines no getpriority wrapper)",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall getpriority (nr",
        },
    }],
    ..DEFAULTS
};
