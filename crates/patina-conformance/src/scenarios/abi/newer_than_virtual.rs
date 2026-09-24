//! abi/newer-than-virtual — a number the vendored table lists but the virtual
//! ABI level predates (`fchroot`, 472, first in Linux 7.3; the registry row is
//! `Absent`) answers ENOSYS through every vehicle, exactly as a kernel of the
//! declared level does — never a trap, never the host's newer semantics.
//! Natively the host kernel must lack the number too: on a kernel that
//! implements it the scenario is not run (`asserts_absent`).

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let r = p.fchroot(AT_FDCWD, 0);
    p.check(
        "a number past the virtual ABI level is ENOSYS",
        r == neg(ENOSYS),
    );
    // The number is judged before its arguments: a kernel that implements
    // it would answer EBADF here.
    let r = p.fchroot(-1, 0);
    p.check("ENOSYS regardless of the arguments", r == neg(ENOSYS));
}

pub const SCENARIO: Scenario = Scenario {
    name: "abi/newer-than-virtual",
    run,
    asserts_absent: &[Syscall::N_fchroot],
    symbols: &["syscall"],
    ..DEFAULTS
};
