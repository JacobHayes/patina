//! proc/wait — childless wait4/waitid answers: ECHILD for any child, the
//! process itself and its process group, with and without WNOHANG, and
//! invalid option EINVAL (checked before any child is looked for,
//! kernel/exit.c kernel_wait4).

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::vehicle::Vehicle;
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
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/wait",
    run,
    covers: &[Syscall::N_wait4, Syscall::N_waitid, Syscall::N_getpid],
    symbols: &["waitid", "getpid"],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::ALL,
        what: "wait4 answers ECHILD whatever its options (native shim sud/signal_process.rs sys_wait4, which the C waitpid dispatches to as well), where the kernel refuses an unknown option bit with EINVAL before looking for a child (kernel/exit.c kernel_wait4)",
        failure: Failure::Differs(&[
            Difference::field(9, "wait4", "errno", Observed::Str("ECHILD")),
            Difference::check(10, "wait4 with an unknown option bit is EINVAL"),
        ]),
    }],
    ..DEFAULTS
};
