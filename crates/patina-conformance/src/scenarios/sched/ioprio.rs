//! sched/ioprio — I/O priority (block/ioprio.c) of the caller:
//!
//! * the best-effort class takes a level 0..7 and reads back (for pid 0 and
//!   the caller's own pid); the idle class is open to anyone; so is going
//!   back to best effort, at any level;
//! * the realtime class needs `CAP_SYS_NICE` or `CAP_SYS_ADMIN` (`EPERM`);
//!   an unknown class, and an unknown `which` to either row, are `EINVAL`; a
//!   pid no process has is `ESRCH`.
//!
//! Only the caller's own priority is read or set: `IOPRIO_WHO_USER` would
//! reach every process of the user. What a task that never set one reads is
//! not asserted (the default changed across releases).

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, Who, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

const WHO_PROCESS: i32 = 1;
const CLASS_RT: i64 = 1;
const CLASS_BE: i64 = 2;
const CLASS_IDLE: i64 = 3;
/// `IOPRIO_CLASS_INVALID`: no class.
const CLASS_UNKNOWN: i64 = 7;

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;
    p.check(
        "best effort at level 4",
        p.ioprio_set(WHO_PROCESS, Who::Caller, CLASS_BE, 4) == 0,
    );
    p.check(
        "reads back",
        p.ioprio_get(WHO_PROCESS, Who::Caller, true) == (CLASS_BE << 13) | 4,
    );
    p.check(
        "best effort at level 7 for the caller's own pid",
        p.ioprio_set(WHO_PROCESS, Who::Own(pid), CLASS_BE, 7) == 0,
    );
    p.check(
        "reads back",
        p.ioprio_get(WHO_PROCESS, Who::Own(pid), true) == (CLASS_BE << 13) | 7,
    );
    p.check(
        "the idle class is open to anyone",
        p.ioprio_set(WHO_PROCESS, Who::Caller, CLASS_IDLE, 0) == 0,
    );
    p.check(
        "reads back",
        p.ioprio_get(WHO_PROCESS, Who::Caller, true) == CLASS_IDLE << 13,
    );
    p.check(
        "and back to best effort at level 0",
        p.ioprio_set(WHO_PROCESS, Who::Caller, CLASS_BE, 0) == 0,
    );
    p.check(
        "reads back",
        p.ioprio_get(WHO_PROCESS, Who::Caller, true) == CLASS_BE << 13,
    );
    p.check(
        "the realtime class is EPERM",
        p.ioprio_set(WHO_PROCESS, Who::Caller, CLASS_RT, 0) == neg(EPERM),
    );
    p.check(
        "an unknown class is EINVAL",
        p.ioprio_set(WHO_PROCESS, Who::Caller, CLASS_UNKNOWN, 0) == neg(EINVAL),
    );
    p.check(
        "an unknown which is EINVAL to ioprio_set",
        p.ioprio_set(4, Who::Caller, CLASS_BE, 0) == neg(EINVAL),
    );
    p.check(
        "and to ioprio_get",
        p.ioprio_get(4, Who::Caller, true) == neg(EINVAL),
    );
    p.check(
        "ioprio_set of a pid no process has is ESRCH",
        p.ioprio_set(WHO_PROCESS, Who::Missing, CLASS_BE, 0) == neg(ESRCH),
    );
    p.check(
        "ioprio_get of it is ESRCH",
        p.ioprio_get(WHO_PROCESS, Who::Missing, true) == neg(ESRCH),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sched/ioprio",
    run,
    covers: &[Syscall::N_ioprio_set, Syscall::N_ioprio_get],
    symbols: &["syscall", "getpid"],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
