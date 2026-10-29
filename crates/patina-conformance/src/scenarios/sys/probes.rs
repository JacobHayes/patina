//! sys/probes — the sandboxing facilities patina does not model, as far as
//! libraries ask what the kernel offers before using them:
//!
//! * `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
//!   answers the ABI version (4 on the pinned 6.8 kernel);
//! * `seccomp(SECCOMP_GET_ACTION_AVAIL)` answers 0 for each action the
//!   kernel knows, `EOPNOTSUPP` for any other, `EINVAL` for a flag, and an
//!   operation the kernel does not have is `EINVAL`;
//! * `prctl(PR_GET_SECCOMP)` reads 0: no mode is entered.
//!
//! Building a ruleset or entering a seccomp mode is a named stop under
//! patina (the registry's traps), not a comparison against the host.

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const LANDLOCK_CREATE_RULESET_VERSION: i64 = 1;
const SECCOMP_GET_ACTION_AVAIL: i64 = 2;
/// No `SECCOMP_SET_MODE_*`/`SECCOMP_GET_*` operation.
const UNKNOWN_OPERATION: i64 = 99;
/// The actions 6.8 lists: kill process, kill thread, trap, errno, user
/// notification, trace, log, allow.
const KNOWN_ACTIONS: [u32; 8] = [
    0x8000_0000,
    0x0000_0000,
    0x0003_0000,
    0x0005_0000,
    0x7fc0_0000,
    0x7ff0_0000,
    0x7ffc_0000,
    0x7fff_0000,
];
/// No `SECCOMP_RET_*` action.
const UNKNOWN_ACTION: u32 = 0x1234_0000;

pub fn run(p: &Probe) {
    p.check(
        "the Landlock version query answers the ABI version 4",
        p.call_observed(
            Syscall::N_landlock_create_ruleset,
            [0, 0, LANDLOCK_CREATE_RULESET_VERSION, 0, 0, 0],
        ) == 4,
    );
    let seccomp = |op: i64, flags: i64, action: &u32| {
        p.call_observed(
            Syscall::N_seccomp,
            [op, flags, action as *const u32 as i64, 0, 0, 0],
        )
    };
    for action in KNOWN_ACTIONS {
        p.check(
            "a known seccomp action is available",
            seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0,
        );
    }
    p.check(
        "an unknown action is EOPNOTSUPP",
        seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &UNKNOWN_ACTION) == neg(EOPNOTSUPP),
    );
    p.check(
        "an action query with a flag is EINVAL",
        seccomp(SECCOMP_GET_ACTION_AVAIL, 1, &KNOWN_ACTIONS[0]) == neg(EINVAL),
    );
    p.check(
        "an unknown operation is EINVAL",
        seccomp(UNKNOWN_OPERATION, 0, &KNOWN_ACTIONS[0]) == neg(EINVAL),
    );
    p.check(
        "PR_GET_SECCOMP reads 0",
        p.prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/probes",
    run,
    // glibc has no wrapper for these rows: the libc spelling would be
    // `syscall(2)` again.
    vehicles: &[Vehicle::Syscall],
    covers: &[Syscall::N_landlock_create_ruleset, Syscall::N_seccomp],
    needs: &[Need::Landlock],
    kernel_floor: Some(KernelFloor {
        release: "6.7",
        why: "Landlock ABI 4 (security/landlock/syscalls.c)",
    }),
    ..DEFAULTS
};
