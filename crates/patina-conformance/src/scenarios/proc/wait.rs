//! proc/wait — childless wait4/waitid answers: ECHILD, WNOHANG, and invalid
//! option EINVAL.

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
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/wait",
    run,
    covers: &[Syscall::N_wait4, Syscall::N_waitid],
    symbols: &["waitid"],
    ..DEFAULTS
};
