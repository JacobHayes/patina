//! fs/newer_than_virtual — filesystem rows the vendored table lists past the
//! virtual ABI level answer ENOSYS through every vehicle, exactly as a kernel
//! of the declared level does: the `*xattrat` rows (Linux 6.13) and
//! file_getattr/file_setattr (Linux 6.17). The number is judged before its
//! arguments, so arguments a kernel implementing the row would refuse (a
//! closed descriptor, NULL pointers) still answer ENOSYS. Natively the host
//! kernel must lack the rows too; on a kernel that implements them the
//! scenario is not run (`asserts_absent`).

use crate::catalog::{DEFAULTS, Scenario};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    for row in [
        Syscall::N_setxattrat,
        Syscall::N_getxattrat,
        Syscall::N_listxattrat,
        Syscall::N_removexattrat,
        Syscall::N_file_getattr,
        Syscall::N_file_setattr,
    ] {
        let r = p.absent(row, &[("dirfd", 4000), ("path", 0), ("flags", 0)]);
        p.check(
            "a filesystem row past the virtual ABI level is ENOSYS",
            r == neg(ENOSYS),
        );
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/newer_than_virtual",
    run,
    // glibc has no wrapper for these rows: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    asserts_absent: &[
        Syscall::N_setxattrat,
        Syscall::N_getxattrat,
        Syscall::N_listxattrat,
        Syscall::N_removexattrat,
        Syscall::N_file_getattr,
        Syscall::N_file_setattr,
    ],
    ..DEFAULTS
};
