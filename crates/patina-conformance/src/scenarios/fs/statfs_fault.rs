//! fs/statfs_fault — statfs / fstatfs into a NULL buffer: the kernel fills
//! the result with copy_to_user and answers EFAULT (fs/statfs.c
//! do_statfs_native), whatever the path or descriptor names; a closed
//! descriptor is still EBADF first. Its own scenario, because a door that
//! writes through the guest's NULL instead ends the whole run.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    let fd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", fd >= 0);
    p.check(
        "statfs into a NULL buffer is EFAULT",
        p.statfs(&root, true).0 == neg(EFAULT),
    );
    p.check(
        "a missing path is ENOENT before the buffer",
        p.statfs(&format!("{root}/missing"), true).0 == neg(ENOENT),
    );
    p.check(
        "fstatfs into a NULL buffer is EFAULT",
        p.fstatfs(fd, true).0 == neg(EFAULT),
    );
    p.check(
        "a closed descriptor is EBADF before the buffer",
        p.fstatfs(4000, true).0 == neg(EBADF),
    );
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/statfs_fault",
    run,
    covers: &[
        Syscall::N_statfs,
        Syscall::N_fstatfs,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &["statfs", "fstatfs", "openat", "close"],
    ..DEFAULTS
};
