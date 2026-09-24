//! proc/pgrp — process groups and sessions of a process that leads its own
//! group but not its session (the harness starts the native run so; kernel/
//! sys.c):
//!
//! * (x86_64) `getpgrp` answers the caller's pid — the generic table has no
//!   `getpgrp` row; `getpgid(0)` says the same on both;
//! * `setpgid(0, 0)` and `setpgid(pid, pid)` keep the group it leads; a
//!   negative group is `EINVAL`; a pid no process has `ESRCH`; a group no
//!   process of its session leads `EPERM`;
//! * `setsid` of a group leader is `EPERM`.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, Who, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let pid = p.getpid();
    p.check("the caller leads its process group", p.getpgid(0) == pid);
    #[cfg(target_arch = "x86_64")]
    p.check("getpgrp answers it", p.getpgrp() == pid);
    let pid = pid as i32;
    p.check(
        "setpgid(0, 0) keeps the group",
        p.setpgid(Who::Caller, Who::Caller) == 0,
    );
    p.check(
        "setpgid(pid, pid) too",
        p.setpgid(Who::Own(pid), Who::Own(pid)) == 0,
    );
    p.check(
        "a negative group is EINVAL",
        p.setpgid(Who::Caller, Who::Raw(-1)) == neg(EINVAL),
    );
    p.check(
        "a pid no process has is ESRCH",
        p.setpgid(Who::Missing, Who::Caller) == neg(ESRCH),
    );
    p.check(
        "a group nobody in the session leads is EPERM",
        p.setpgid(Who::Caller, Who::Missing) == neg(EPERM),
    );
    p.check(
        "setsid of a group leader is EPERM",
        p.setsid() == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/pgrp",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_getpgrp,
        Syscall::N_setpgid,
        Syscall::N_setsid,
    ],
    symbols: &["getpid", "setpgid", "setsid", "syscall"],
    ..DEFAULTS
};
