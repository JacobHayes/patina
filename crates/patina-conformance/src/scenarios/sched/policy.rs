//! sched/policy — scheduling policy and static priority (kernel/sched/
//! syscalls.c):
//!
//! * `sched_yield` succeeds;
//! * a process runs `SCHED_OTHER` at priority 0, for pid 0 and its own pid;
//!   a negative pid is `EINVAL`, one no process has `ESRCH`; a NULL param is
//!   `EINVAL`;
//! * the priority range per policy: 1..99 for `SCHED_FIFO`/`SCHED_RR`, 0 for
//!   `SCHED_OTHER`/`SCHED_BATCH`/`SCHED_IDLE`/`SCHED_DEADLINE`; an unknown
//!   policy (-1, the unimplemented 4, 8) is `EINVAL`;
//! * a normal policy takes only priority 0 and a realtime one only 1..99
//!   (`EINVAL` otherwise); an unknown policy is `EINVAL`; init's policy,
//!   root's, is not the caller's to set (`EPERM`, `check_same_owner`);
//! * `sched_rr_get_interval` of a normal task answers its slice (the host
//!   scheduler's, recorded as under a second);
//! * an unprivileged caller moves between the normal policies, but with
//!   `RLIMIT_RTPRIO` at 0 a realtime one is `EPERM`; it may set
//!   `SCHED_RESET_ON_FORK` and not clear it again; with `RLIMIT_NICE` at 0 it
//!   may enter `SCHED_IDLE` and not leave it (`EPERM`).
//!
//! The limits are lowered to 0 here (what an unprivileged process usually
//! has; lowering is always allowed), so the refusals do not hang on the
//! host's `limits.conf`. The process ends in `SCHED_IDLE`, so that comes
//! last.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, Who, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

const SCHED_DEADLINE: i32 = 6;
const RESET_ON_FORK: i32 = 0x4000_0000;

pub fn run(p: &Probe) {
    p.check("sched_yield succeeds", p.sched_yield() == 0);
    let pid = p.getpid() as i32;
    p.check(
        "a process runs SCHED_OTHER",
        p.sched_getscheduler(Who::Caller) == i64::from(SCHED_OTHER),
    );
    p.check(
        "its own pid too",
        p.sched_getscheduler(Who::Own(pid)) == i64::from(SCHED_OTHER),
    );
    p.check(
        "a pid no process has is ESRCH",
        p.sched_getscheduler(Who::Missing) == neg(ESRCH),
    );
    p.check(
        "a negative pid is EINVAL",
        p.sched_getscheduler(Who::Raw(-1)) == neg(EINVAL),
    );
    let (r, priority) = p.sched_getparam(Who::Caller, false);
    p.check("at priority 0", r == 0 && priority == 0);
    p.check(
        "sched_getparam with a NULL param is EINVAL",
        p.sched_getparam(Who::Caller, true).0 == neg(EINVAL),
    );
    p.check(
        "sched_getparam of a pid no process has is ESRCH",
        p.sched_getparam(Who::Missing, false).0 == neg(ESRCH),
    );
    p.check(
        "sched_getparam of a negative pid is EINVAL",
        p.sched_getparam(Who::Raw(-1), false).0 == neg(EINVAL),
    );

    for (policy, min, max) in [
        (SCHED_OTHER, 0, 0),
        (SCHED_FIFO, 1, 99),
        (SCHED_RR, 1, 99),
        (SCHED_BATCH, 0, 0),
        (SCHED_IDLE, 0, 0),
        (SCHED_DEADLINE, 0, 0),
    ] {
        p.check(
            "the policy's highest priority",
            p.sched_get_priority_max(policy) == max,
        );
        p.check(
            "the policy's lowest priority",
            p.sched_get_priority_min(policy) == min,
        );
    }
    for policy in [-1, 4, 8] {
        p.check(
            "an unknown policy has no priority range",
            p.sched_get_priority_max(policy) == neg(EINVAL)
                && p.sched_get_priority_min(policy) == neg(EINVAL),
        );
    }

    p.check(
        "sched_setparam keeps priority 0",
        p.sched_setparam(Who::Caller, Some(0)) == 0,
    );
    p.check(
        "a normal policy takes no other priority",
        p.sched_setparam(Who::Caller, Some(1)) == neg(EINVAL),
    );
    p.check(
        "sched_setparam with a NULL param is EINVAL",
        p.sched_setparam(Who::Caller, None) == neg(EINVAL),
    );
    p.check(
        "sched_setparam of a pid no process has is ESRCH",
        p.sched_setparam(Who::Missing, Some(0)) == neg(ESRCH),
    );
    p.check(
        "sched_setscheduler to SCHED_OTHER at 0",
        p.sched_setscheduler(Who::Caller, SCHED_OTHER, 0) == 0,
    );
    p.check(
        "SCHED_OTHER at priority 1 is EINVAL",
        p.sched_setscheduler(Who::Caller, SCHED_OTHER, 1) == neg(EINVAL),
    );
    p.check(
        "SCHED_FIFO at priority 0 is EINVAL",
        p.sched_setscheduler(Who::Caller, SCHED_FIFO, 0) == neg(EINVAL),
    );
    p.check(
        "an unknown policy is EINVAL",
        p.sched_setscheduler(Who::Caller, 99, 0) == neg(EINVAL),
    );
    p.require_unprivileged();
    p.check(
        "sched_setscheduler of init, root's process, is EPERM",
        p.sched_setscheduler(Who::Init, SCHED_OTHER, 0) == neg(EPERM),
    );
    let (r, _) = p.sched_rr_get_interval(Who::Caller);
    p.check(
        "sched_rr_get_interval answers a normal task's slice",
        r == 0,
    );
    p.check(
        "of a pid no process has is ESRCH",
        p.sched_rr_get_interval(Who::Missing).0 == neg(ESRCH),
    );
    p.check(
        "of a negative pid is EINVAL",
        p.sched_rr_get_interval(Who::Raw(-1)).0 == neg(EINVAL),
    );

    p.check(
        "an unprivileged caller may enter SCHED_BATCH",
        p.sched_setscheduler(Who::Caller, SCHED_BATCH, 0) == 0,
    );
    p.check(
        "which reads back",
        p.sched_getscheduler(Who::Caller) == i64::from(SCHED_BATCH),
    );
    p.check(
        "and leave it",
        p.sched_setscheduler(Who::Caller, SCHED_OTHER, 0) == 0,
    );
    p.check(
        "RLIMIT_RTPRIO lowers to 0",
        p.setrlimit(RLIMIT_RTPRIO as i32, 0, 0) == 0,
    );
    p.check(
        "then a realtime policy is EPERM",
        p.sched_setscheduler(Who::Caller, SCHED_FIFO, 1) == neg(EPERM),
    );
    p.check(
        "SCHED_RESET_ON_FORK may be set",
        p.sched_setscheduler(Who::Caller, SCHED_OTHER | RESET_ON_FORK, 0) == 0,
    );
    p.check(
        "and reads back with the policy",
        p.sched_getscheduler(Who::Caller) == i64::from(SCHED_OTHER | RESET_ON_FORK),
    );
    p.check(
        "but not cleared again",
        p.sched_setscheduler(Who::Caller, SCHED_OTHER, 0) == neg(EPERM),
    );
    p.check(
        "RLIMIT_NICE lowers to 0",
        p.setrlimit(RLIMIT_NICE as i32, 0, 0) == 0,
    );
    p.check(
        "SCHED_IDLE may be entered",
        p.sched_setscheduler(Who::Caller, SCHED_IDLE | RESET_ON_FORK, 0) == 0,
    );
    p.check(
        "and reads back",
        p.sched_getscheduler(Who::Caller) == i64::from(SCHED_IDLE | RESET_ON_FORK),
    );
    p.check(
        "but not left without the nice limit",
        p.sched_setscheduler(Who::Caller, SCHED_OTHER | RESET_ON_FORK, 0) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sched/policy",
    run,
    covers: &[
        Syscall::N_sched_yield,
        Syscall::N_sched_getscheduler,
        Syscall::N_sched_setscheduler,
        Syscall::N_sched_getparam,
        Syscall::N_sched_setparam,
        Syscall::N_sched_get_priority_max,
        Syscall::N_sched_get_priority_min,
        Syscall::N_sched_rr_get_interval,
    ],
    symbols: &["sched_yield", "syscall", "getpid", "setrlimit"],
    needs: &[Need::Unprivileged, Need::RootInit],
    ..DEFAULTS
};
