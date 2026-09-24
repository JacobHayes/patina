//! cred/groups — supplementary groups (kernel/groups.c):
//!
//! * `getgroups(0, NULL)` answers the count; a buffer of exactly the count
//!   is filled and answers it; a larger one answers it too; one short of it
//!   is `EINVAL` (unless that is 0, the count query), and so is a negative
//!   size;
//! * the kernel's bound is `NGROUPS_MAX` = 65536, which
//!   `sysconf(_SC_NGROUPS_MAX)` reports;
//! * `setgroups` checks the privilege first: an unprivileged caller is
//!   `EPERM` before its size is looked at (above the bound, negative, an
//!   empty list, the current list).
//!
//! The count is the host's: it is recorded by relation
//! (`Norm::Relative("ngroups")`), so the calls that take it back compare
//! with the virtual kernel's own count.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{GroupsSize, Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

const NGROUPS_MAX: i32 = 65536;

pub fn run(p: &Probe) {
    let (count, _) = p.getgroups(GroupsSize::Raw(0));
    p.require("getgroups answers the count", count >= 0);
    let count = count as i32;
    let (r, list) = p.getgroups(GroupsSize::Count(count));
    p.check(
        "a buffer of the count is filled",
        r == i64::from(count) && list.len() == count as usize,
    );
    p.check(
        "a larger buffer answers the count",
        p.getgroups(GroupsSize::Raw(NGROUPS_MAX)).0 == i64::from(count),
    );
    let (r, _) = p.getgroups(GroupsSize::Short(count));
    p.check(
        "one short of the count is EINVAL, unless it is 0 (the count query)",
        if count == 1 {
            r == i64::from(count)
        } else {
            r == neg(EINVAL)
        },
    );
    p.check(
        "a negative size is EINVAL",
        p.getgroups(GroupsSize::Raw(-1)).0 == neg(EINVAL),
    );
    // SAFETY: sysconf reads a constant.
    let bound = unsafe { sysconf(_SC_NGROUPS_MAX) };
    p.mark(
        "sysconf",
        &[
            ("name", Value::from("_SC_NGROUPS_MAX")),
            ("value", Value::from(bound)),
        ],
    );
    p.check("NGROUPS_MAX is 65536", bound == i64::from(NGROUPS_MAX));

    p.check(
        "setgroups above the bound is EPERM, before the size is looked at",
        p.setgroups(GroupsSize::Raw(NGROUPS_MAX + 1), None) == neg(EPERM),
    );
    p.check(
        "a negative size is EPERM too",
        p.setgroups(GroupsSize::Raw(-1), None) == neg(EPERM),
    );
    p.check(
        "an empty list is EPERM",
        p.setgroups(GroupsSize::Raw(0), None) == neg(EPERM),
    );
    p.check(
        "the current list is EPERM too",
        p.setgroups(GroupsSize::Count(count), Some(&list)) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "cred/groups",
    run,
    covers: &[Syscall::N_getgroups, Syscall::N_setgroups],
    symbols: &["setgroups", "sysconf", "syscall"],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
