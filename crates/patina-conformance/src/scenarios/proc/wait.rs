//! proc/wait — childless wait4/waitid answers: ECHILD for any child, the
//! process itself (by pid or through its pidfd) and its process group, with
//! and without WNOHANG, and invalid option EINVAL and wait4's `INT_MIN` pid
//! ESRCH (checked before any child is looked for, kernel/exit.c
//! kernel_wait4); waitid judges its `which` and id first too
//! (kernel_waitid_prepare): a `P_PID` pid of 0, a negative `P_PIDFD` id and
//! an unknown `which` are EINVAL, a `P_PIDFD` descriptor that is no pidfd
//! EBADF.

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;

/// A `which` waitid does not define.
const UNKNOWN_WHICH: idtype_t = 99;

pub fn run(p: &Probe) {
    p.check(
        "wait4(-1) without children is ECHILD",
        p.wait4(-1, 0).0 == neg(ECHILD),
    );
    p.check(
        "wait4(-1,WNOHANG) without children is ECHILD",
        p.wait4(-1, WNOHANG).0 == neg(ECHILD),
    );
    let own = p.getpid();
    let mut status = 0;
    let r = p.call_unrecorded(
        Syscall::N_wait4,
        [own, &mut status as *mut i32 as i64, WNOHANG as i64, 0, 0, 0],
    );
    p.rec
        .event("wait4", r)
        .arg("pid", "self")
        .arg("options", WNOHANG)
        .field("status", status)
        .emit();
    p.check("wait4 on the process itself is ECHILD", r == neg(ECHILD));
    p.check(
        "wait4(0) (the process group) without children is ECHILD",
        p.wait4(0, 0).0 == neg(ECHILD),
    );
    p.check(
        "wait4 with an unknown option bit is EINVAL",
        p.wait4(-1, 0x100).0 == neg(EINVAL),
    );
    p.check(
        "waitid(P_ALL) without children is ECHILD",
        p.waitid(P_ALL as i32, 0, WEXITED).0 == neg(ECHILD),
    );
    p.check(
        "waitid WNOHANG without children is ECHILD",
        p.waitid(P_ALL as i32, 0, WEXITED | WNOHANG).0 == neg(ECHILD),
    );
    p.check(
        "waitid invalid options are EINVAL",
        p.waitid(P_ALL as i32, 0, 0x4000_0000).0 == neg(EINVAL),
    );
    let pidfd = p.pidfd_open(own as i32, 0);
    p.require("open the caller's pidfd", pidfd >= 0);
    for (which, id, what, errno, label) in [
        (P_PID, 0, "0", EINVAL, "waitid(P_PID, 0) is EINVAL"),
        (P_PIDFD, -1, "-1", EINVAL, "waitid(P_PIDFD, -1) is EINVAL"),
        (
            P_PIDFD,
            0,
            "stdin",
            EBADF,
            "waitid(P_PIDFD) of a descriptor that is no pidfd is EBADF",
        ),
        (
            P_PIDFD,
            pidfd,
            "self-pidfd",
            ECHILD,
            "waitid(P_PIDFD) of the process itself is ECHILD",
        ),
        (
            UNKNOWN_WHICH,
            0,
            "0",
            EINVAL,
            "waitid of an unknown which is EINVAL",
        ),
    ] {
        // SAFETY: an all-zero siginfo is a valid out-parameter.
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        let r = p.observed(
            Syscall::N_waitid,
            [
                which as i64,
                id as i64,
                &mut info as *mut siginfo_t as i64,
                (WEXITED | WNOHANG) as i64,
                0,
                0,
            ],
            &[("idtype", which.into()), ("id", what.into())],
        );
        p.check(label, r == neg(errno));
    }
    p.close(pidfd);
    p.check(
        "wait4 with WEXITED, a waitid option, is EINVAL",
        p.wait4(-1, WEXITED).0 == neg(EINVAL),
    );
    p.check(
        "wait4(INT_MIN) is ESRCH",
        p.wait4(i32::MIN, WNOHANG).0 == neg(ESRCH),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/wait",
    run,
    covers: &[Syscall::N_wait4, Syscall::N_waitid, Syscall::N_getpid],
    symbols: &["waitid", "getpid"],
    ..DEFAULTS
};
