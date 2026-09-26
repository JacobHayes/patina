//! proc/wait — childless wait4/waitid answers: ECHILD for any child, the
//! process itself and its process group, with and without WNOHANG, and
//! invalid option EINVAL and wait4's `INT_MIN` pid ESRCH (checked before any
//! child is looked for, kernel/exit.c kernel_wait4).

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;

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
