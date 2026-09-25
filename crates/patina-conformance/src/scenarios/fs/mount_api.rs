//! fs/mount_api — the file-descriptor mount API (fs/fsopen.c,
//! fs/namespace.c), for the unprivileged caller the virtual kernel models.
//! Every row but `fsconfig` needs `CAP_SYS_ADMIN` in the mount namespace's
//! user namespace (`may_mount`):
//!
//! * `fsopen`, `fspick`, `fsmount` and `move_mount` check it FIRST, so an
//!   unprivileged caller is `EPERM` whatever flags, names and descriptors it
//!   passes;
//! * `mount_setattr` refuses an unknown flag (`EINVAL`), a size past a page
//!   (`E2BIG`) and one short of `MOUNT_ATTR_SIZE_VER0` (`EINVAL`) first, then
//!   is `EPERM` before it reads the attributes;
//! * `fsconfig` has no capability check: it validates the descriptor number
//!   (negative: `EINVAL`), the command (unknown: `EOPNOTSUPP`) and its
//!   argument shape (`EINVAL`), then wants an open (`EBADF`) filesystem
//!   context (anything else: `EINVAL`), which only the refused rows create.
//!
//! Every call is one root would be refused too (an unknown flag, a missing
//! path, no descriptor, or no attributes), so nothing is ever mounted. The
//! libc vehicle goes through glibc 2.36's wrappers of the same names, which
//! the shim does not define (registry `Absent`): it reaches them through
//! `dlsym`.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

/// Every flag bit the rows' flag words leave undefined in the low byte.
const UNKNOWN_FLAGS: i64 = 0xfe;
/// No `MOVE_MOUNT_*` flag.
const UNKNOWN_MOVE_FLAG: i64 = 1 << 20;
/// No `AT_*` flag `mount_setattr` takes.
const UNKNOWN_AT_FLAG: i64 = 0x1;
/// `MOUNT_ATTR_SIZE_VER0`, `sizeof(struct mount_attr)`.
const MOUNT_ATTR_SIZE: i64 = 32;
/// `FSCONFIG_SET_FLAG` and `FSCONFIG_CMD_CREATE`.
const FSCONFIG_SET_FLAG: i64 = 0;
const FSCONFIG_CMD_CREATE: i64 = 6;
/// No `FSCONFIG_*` command.
const FSCONFIG_UNKNOWN: i64 = 99;
/// A descriptor number the run never opens.
const CLOSED: i64 = 4000;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let root = p.dir();
    let dir = CString::new(root.as_str()).unwrap();
    let missing = CString::new(format!("{root}/missing")).unwrap();

    // A row that checks the capability first is asked once, with every
    // argument it would check afterwards invalid.
    for (row, args, label) in [
        (
            Syscall::N_fsopen,
            [0, UNKNOWN_FLAGS, 0, 0, 0, 0],
            "fsopen is EPERM (no CAP_SYS_ADMIN) before its flags and name are read",
        ),
        (
            Syscall::N_fspick,
            [CLOSED, missing.as_ptr() as i64, UNKNOWN_FLAGS, 0, 0, 0],
            "fspick is EPERM before its flags and path",
        ),
        (
            Syscall::N_fsmount,
            [-1, UNKNOWN_FLAGS, 0, 0, 0, 0],
            "fsmount is EPERM before its flags and descriptor",
        ),
        (
            Syscall::N_move_mount,
            [
                AT_FDCWD as i64,
                missing.as_ptr() as i64,
                AT_FDCWD as i64,
                missing.as_ptr() as i64,
                UNKNOWN_MOVE_FLAG,
                0,
            ],
            "move_mount is EPERM before its flags and paths",
        ),
    ] {
        p.check(label, p.call_observed(row, args) == neg(EPERM));
    }

    let attr = [0u8; 32];
    let setattr = |flags: i64, uattr: *const u8, size: i64| {
        p.call_observed(
            Syscall::N_mount_setattr,
            [
                AT_FDCWD as i64,
                dir.as_ptr() as i64,
                flags,
                uattr as i64,
                size,
                0,
            ],
        )
    };
    p.check(
        "mount_setattr with an unknown flag is EINVAL",
        setattr(UNKNOWN_AT_FLAG, attr.as_ptr(), MOUNT_ATTR_SIZE) == neg(EINVAL),
    );
    p.check(
        "a size past a page is E2BIG",
        setattr(0, attr.as_ptr(), 8192) == neg(E2BIG),
    );
    p.check(
        "a size short of MOUNT_ATTR_SIZE_VER0 is EINVAL",
        setattr(0, attr.as_ptr(), 8) == neg(EINVAL),
    );
    p.check(
        "then it is EPERM, before the attributes are read",
        setattr(0, std::ptr::null(), MOUNT_ATTR_SIZE) == neg(EPERM),
    );

    let fsconfig = |fd: i64, cmd: i64| p.call_observed(Syscall::N_fsconfig, [fd, cmd, 0, 0, 0, 0]);
    p.check(
        "fsconfig of a negative descriptor is EINVAL",
        fsconfig(-1, FSCONFIG_CMD_CREATE) == neg(EINVAL),
    );
    p.check(
        "an unknown command is EOPNOTSUPP",
        fsconfig(CLOSED, FSCONFIG_UNKNOWN) == neg(EOPNOTSUPP),
    );
    p.check(
        "FSCONFIG_SET_FLAG without a key is EINVAL before the descriptor",
        fsconfig(CLOSED, FSCONFIG_SET_FLAG) == neg(EINVAL),
    );
    p.check(
        "a closed descriptor is EBADF",
        fsconfig(CLOSED, FSCONFIG_CMD_CREATE) == neg(EBADF),
    );
    let fd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", fd >= 0);
    p.check(
        "a descriptor that is no filesystem context is EINVAL",
        fsconfig(fd as i64, FSCONFIG_CMD_CREATE) == neg(EINVAL),
    );
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/mount_api",
    run,
    covers: &[
        Syscall::N_fsopen,
        Syscall::N_fspick,
        Syscall::N_fsmount,
        Syscall::N_move_mount,
        Syscall::N_mount_setattr,
        Syscall::N_fsconfig,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "fsopen",
        "fspick",
        "fsmount",
        "move_mount",
        "mount_setattr",
        "fsconfig",
        "openat",
        "close",
    ],
    resolves: &[
        "fsopen",
        "fspick",
        "fsmount",
        "move_mount",
        "mount_setattr",
        "fsconfig",
    ],
    needs: &[Need::Unprivileged],
    gaps: &[Gap {
        status: Status::Pending(Arc::Privileged),
        vehicles: &[Vehicle::Libc],
        what: "the shim defines none of glibc's mount-API wrappers (registry `Absent`): a guest importing one is refused by the pre-run audit, and `dlsym` finds none (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the libc leg stops at its first call",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Exit(101),
            diagnostic: "fs/mount_api: cannot continue: glibc's fsopen resolves",
        },
    }],
    ..DEFAULTS
};
