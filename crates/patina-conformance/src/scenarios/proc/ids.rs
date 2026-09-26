//! proc/ids — process/thread id relations for a single-process guest, its
//! process group and session, kill(0)/kill(-1) process selection, and
//! `kill(1)` and `tgkill(1, 1)` of init, which is root's (`EPERM`,
//! `kill_ok_by_cred`); then
//! the group and session rows of a process that leads its own group but not
//! its session (the harness starts the native run so; kernel/sys.c):
//!
//! * (x86_64) `getpgrp` answers the caller's pid — the generic table has no
//!   `getpgrp` row; `getpgid(0)` says the same on both;
//! * `setpgid(0, 0)` and `setpgid(pid, pid)` keep the group it leads; a
//!   negative group is `EINVAL`; a pid no process has `ESRCH`; a group no
//!   process of its session leads `EPERM`;
//! * `setsid` of a group leader is `EPERM`.

use crate::catalog::{DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, Who, neg};
use libc::*;

pub fn run(p: &Probe) {
    let pid = p.getpid() as pid_t;
    p.gettid();
    let ppid = p.getppid();
    let pgid = p.getpgid(0);
    let sid = p.getsid(0);
    p.check("parent pid is nonnegative", ppid >= 0);
    p.check("session id is positive", sid > 0);
    p.check("getpgid(pid) equals getpgid(0)", p.getpgid(pid) == pgid);
    p.check("getsid(pid) equals getsid(0)", p.getsid(pid) == sid);
    p.check("tgkill(pid,pid,0) succeeds", p.tgkill(pid, pid, 0) == 0);
    p.check(
        "kill(0,0) succeeds for our process group",
        p.kill(0, 0) == 0,
    );
    p.check(
        "kill(-1,0) succeeds when at least one process is signalable",
        p.kill(-1, 0) == 0,
    );
    for (row, args, named, label) in [
        (
            Syscall::N_kill,
            [1, 0, 0, 0, 0, 0],
            vec![("pid", "init".into()), ("sig", 0.into())],
            "kill(1,0) of init, root's process, is EPERM",
        ),
        (
            Syscall::N_tgkill,
            [1, 1, 0, 0, 0, 0],
            vec![
                ("tgid", "init".into()),
                ("tid", "init".into()),
                ("sig", 0.into()),
            ],
            "tgkill(1,1,0) of init's thread is EPERM",
        ),
    ] {
        p.check(label, p.observed(row, args, &named) == neg(EPERM));
    }

    p.check("the caller leads its process group", pgid == i64::from(pid));
    #[cfg(target_arch = "x86_64")]
    p.check("getpgrp answers it", p.getpgrp() == i64::from(pid));
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
    name: "proc/ids",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_getppid,
        Syscall::N_getpgid,
        Syscall::N_getsid,
        Syscall::N_tgkill,
        Syscall::N_kill,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_getpgrp,
        Syscall::N_setpgid,
        Syscall::N_setsid,
    ],
    symbols: &[
        "getpid", "syscall", "getppid", "gettid", "tgkill", "kill", "setpgid", "setsid",
    ],
    needs: &[Need::Unprivileged, Need::RootInit],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "the virtual pid namespace holds two processes, its init (pid 1) and the guest (pid 2, init's child; registry::INIT_PID/IDENTITY_PID, src/identity.rs): kill(-1, sig) reaches every process but init and the caller, of which there are none, so the kernel's answer for that tree is ESRCH (kill_something_info), where the native oracle's host has other processes of the caller's",
        failure: Failure::Differs(&[
            Difference::field(15, "kill", "errno", Observed::Str("ESRCH")),
            Difference::field(15, "kill", "ret", Observed::Int(-1)),
            Difference::check(
                16,
                "kill(-1,0) succeeds when at least one process is signalable",
            ),
        ]),
    }],
    ..DEFAULTS
};
