//! sys/root — changing the root directory: `chroot` (fs/open.c) looks the
//! path up first (NULL: `EFAULT`; missing: `ENOENT`; no directory:
//! `ENOTDIR`), needs search permission on it (`EACCES`), and only then
//! `CAP_SYS_CHROOT` (`EPERM`). (`pivot_root`, which checks its capability
//! first until 7.0, is sys/admin's.)
//!
//! A root caller's `chroot` of the run directory would change the probe's
//! own root and nothing else.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let root = p.dir();
    let fd = p.openat(AT_FDCWD, &format!("{root}/file"), O_CREAT | O_WRONLY, 0o600);
    p.require("create a regular file", fd >= 0);
    p.close(fd);
    p.require(
        "create a directory nobody may search",
        p.mkdirat(AT_FDCWD, &format!("{root}/sealed"), 0) == 0,
    );
    let path = |name: &str| CString::new(format!("{root}/{name}")).unwrap();
    let (missing, file, sealed, dir) = (
        path("missing"),
        path("file"),
        path("sealed"),
        CString::new(root.as_str()).unwrap(),
    );
    let chroot =
        |path: *const c_char| p.call_observed(Syscall::N_chroot, [path as i64, 0, 0, 0, 0, 0]);
    p.check(
        "chroot of NULL is EFAULT",
        chroot(std::ptr::null()) == neg(EFAULT),
    );
    p.check(
        "chroot of a missing path is ENOENT",
        chroot(missing.as_ptr()) == neg(ENOENT),
    );
    p.check(
        "chroot of a file is ENOTDIR",
        chroot(file.as_ptr()) == neg(ENOTDIR),
    );
    p.check(
        "chroot of a directory without search permission is EACCES",
        chroot(sealed.as_ptr()) == neg(EACCES),
    );

    p.check(
        "chroot of the run directory is EPERM (no CAP_SYS_CHROOT)",
        chroot(dir.as_ptr()) == neg(EPERM),
    );
    // The harness empties the run directory between vehicles.
    p.require(
        "remove the directory nobody may search",
        p.unlinkat(AT_FDCWD, &format!("{root}/sealed"), AT_REMOVEDIR) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/root",
    run,
    covers: &[
        Syscall::N_chroot,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_mkdirat,
        Syscall::N_unlinkat,
    ],
    symbols: &["chroot", "openat", "close", "mkdirat", "unlinkat"],
    needs: &[Need::Unprivileged],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: &[Vehicle::Libc],
            what: "the shim's chroot is a process-class deny-trap (c/posix/signal_process.c chroot) where the unprivileged caller is answered EFAULT, ENOENT, ENOTDIR, EACCES and EPERM",
            failure: Failure::Stops {
                events: 3,
                ending: Ending::Signal(SIGABRT),
                diagnostic: "patina: process spawn reached under patina: chroot",
            },
        },
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: &[
                Vehicle::Syscall,
                #[cfg(target_arch = "x86_64")]
                Vehicle::Raw,
            ],
            what: "chroot is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)) where the unprivileged caller is answered by the path checks and then EPERM",
            failure: Failure::Stops {
                events: 3,
                ending: Ending::Signal(SIGABRT),
                diagnostic: TRAP,
            },
        },
    ],
    ..DEFAULTS
};

#[cfg(target_arch = "x86_64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall chroot (nr 161, class privileged";
#[cfg(target_arch = "aarch64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall chroot (nr 51, class privileged";
