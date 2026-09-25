//! fs/mount — the legacy mount rows (fs/namespace.c), for the unprivileged
//! caller the virtual kernel models. Both need `CAP_SYS_ADMIN` in the mount
//! namespace's user namespace (`may_mount`), checked after the arguments are
//! read:
//!
//! * `mount` copies its strings (`copy_mount_string`, `copy_mount_options`),
//!   looks the target up (`do_mount`: a NULL target is `EFAULT`, a missing one
//!   `ENOENT`), refuses `MS_NOUSER` (`path_mount`: `EINVAL`), and only then is
//!   `EPERM`;
//! * `umount2` refuses an unknown flag (`ksys_umount`: `EINVAL`), looks the
//!   path up (`ENOENT`), and only then is `EPERM` (`can_umount`), before it
//!   asks whether the path is a mount at all.
//!
//! Every call is one root would be refused too: the filesystem type exists
//! nowhere (`ENODEV`), and the run directory is no mount root (`EINVAL`), so
//! nothing is ever mounted or unmounted. The libc vehicle goes through
//! glibc's `mount` and `umount2`, which the shim defines.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

/// `MS_NOUSER`, the flag no caller may pass.
const NOUSER: i64 = 1 << 31;
/// No `UMOUNT_*`/`MNT_*` flag.
const UNKNOWN_UMOUNT_FLAG: i64 = 0x100;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let dir = CString::new(p.dir()).unwrap();
    let missing = CString::new(format!("{}/missing", p.dir())).unwrap();
    let source = c"none";
    let fstype = c"patina-no-such-fs";
    let mount = |target: *const c_char, flags: i64| {
        p.call_observed(
            Syscall::N_mount,
            [
                source.as_ptr() as i64,
                target as i64,
                fstype.as_ptr() as i64,
                flags,
                0,
                0,
            ],
        )
    };
    p.check(
        "mount onto a NULL target is EFAULT: the target is looked up first",
        mount(std::ptr::null(), 0) == neg(EFAULT),
    );
    p.check(
        "mount onto a missing target is ENOENT",
        mount(missing.as_ptr(), 0) == neg(ENOENT),
    );
    p.check(
        "MS_NOUSER is EINVAL before the capability check",
        mount(dir.as_ptr(), NOUSER) == neg(EINVAL),
    );
    p.check(
        "mount onto the run directory is EPERM (no CAP_SYS_ADMIN)",
        mount(dir.as_ptr(), 0) == neg(EPERM),
    );

    let umount = |target: &CString, flags: i64| {
        p.call_observed(
            Syscall::N_umount2,
            [target.as_ptr() as i64, flags, 0, 0, 0, 0],
        )
    };
    p.check(
        "umount2 with an unknown flag is EINVAL before the lookup",
        umount(&missing, UNKNOWN_UMOUNT_FLAG) == neg(EINVAL),
    );
    p.check(
        "umount2 of a missing path is ENOENT",
        umount(&missing, 0) == neg(ENOENT),
    );
    p.check(
        "umount2 of the run directory is EPERM, before it is found to be no mount",
        umount(&dir, 0) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/mount",
    run,
    covers: &[Syscall::N_mount, Syscall::N_umount2],
    symbols: &["mount", "umount2"],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
