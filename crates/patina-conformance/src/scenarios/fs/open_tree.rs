//! fs/open_tree — `open_tree` (fs/namespace.c). Without `OPEN_TREE_CLONE`
//! it needs no privilege: it is an `O_PATH` open of the path (`dentry_open`
//! with `O_PATH`), close-on-exec under `OPEN_TREE_CLOEXEC`, naming the same
//! inode, and unreadable (`EBADF`). An unknown flag, or `AT_RECURSIVE`
//! without `OPEN_TREE_CLONE`, is `EINVAL` first. Cloning the tree (a
//! detached copy of the mount) needs `CAP_SYS_ADMIN` in the mount
//! namespace's user namespace (`may_mount`), checked before the path is
//! looked up, so a clone of a missing path is `EPERM`, not `ENOENT` (root
//! would be told `ENOENT`: nothing is cloned). The libc vehicle goes
//! through glibc 2.36's `open_tree`, which the shim does not define (registry
//! `Absent`): it reaches it through `dlsym`.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

/// `OPEN_TREE_CLONE`.
const CLONE: i64 = 1;
/// No `AT_*` or `OPEN_TREE_*` flag on any kernel (0x2 is 7.0's
/// `OPEN_TREE_NAMESPACE`).
const UNKNOWN_FLAG: i64 = 1 << 30;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let root = p.dir();
    let dir = CString::new(root.as_str()).unwrap();
    let missing = CString::new(format!("{root}/missing")).unwrap();
    let open_tree = |path: &CString, flags: i64| {
        p.call_observed(
            Syscall::N_open_tree,
            [AT_FDCWD as i64, path.as_ptr() as i64, flags, 0, 0, 0],
        )
    };
    p.check(
        "an unknown flag is EINVAL",
        open_tree(&dir, UNKNOWN_FLAG) == neg(EINVAL),
    );
    p.check(
        "AT_RECURSIVE without OPEN_TREE_CLONE is EINVAL",
        open_tree(&dir, AT_RECURSIVE as i64) == neg(EINVAL),
    );
    p.check(
        "a clone is EPERM (no CAP_SYS_ADMIN) before the path is looked up",
        open_tree(&missing, CLONE) == neg(EPERM),
    );
    p.check(
        "a recursive clone is EPERM too",
        open_tree(&missing, CLONE | AT_RECURSIVE as i64) == neg(EPERM),
    );
    p.check(
        "without a clone a missing path is ENOENT",
        open_tree(&missing, 0) == neg(ENOENT),
    );

    let fd = p.call_unrecorded(
        Syscall::N_open_tree,
        [
            AT_FDCWD as i64,
            dir.as_ptr() as i64,
            O_CLOEXEC as i64,
            0,
            0,
            0,
        ],
    );
    p.rec
        .event(Syscall::N_open_tree.name(), fd)
        .arg("flags", "OPEN_TREE_CLOEXEC")
        .norm("ret", Norm::Relative("fd"))
        .emit();
    p.require("open_tree of the run directory needs no privilege", fd >= 0);
    let fd = fd as i32;
    p.check(
        "it is an O_PATH descriptor",
        p.fcntl(fd, F_GETFL, 0) == O_PATH as i64,
    );
    p.check(
        "OPEN_TREE_CLOEXEC sets close-on-exec",
        p.fcntl(fd, F_GETFD, 0) == FD_CLOEXEC as i64,
    );
    p.check(
        "an O_PATH descriptor is unreadable",
        p.read(fd, 1).0 == neg(EBADF),
    );
    let (r, tree) = p.fstat(fd);
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    let (s, opened) = p.fstat(dirfd);
    p.check(
        "it names the run directory's inode",
        r == 0 && s == 0 && tree.map(|t| t.ino) == opened.map(|o| o.ino),
    );
    p.close(dirfd);
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/open_tree",
    run,
    covers: &[
        Syscall::N_open_tree,
        Syscall::N_fcntl,
        Syscall::N_read,
        Syscall::N_fstat,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &["open_tree", "fcntl", "read", "fstat", "openat", "close"],
    resolves: &["open_tree"],
    needs: &[Need::Unprivileged],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: Vehicle::KERNEL,
            what: "open_tree is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)) where the kernel opens an O_PATH descriptor without a clone and answers a clone EPERM",
            failure: Failure::Stops {
                events: 0,
                ending: Ending::Signal(SIGABRT),
                diagnostic: "patina: SUD trapped unsupported syscall open_tree (nr 428, class privileged",
            },
        },
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: &[Vehicle::Libc],
            what: "the shim does not define glibc's open_tree (registry `Absent`): a guest importing it is refused by the pre-run audit, and `dlsym` does not find it (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the libc leg stops at its first call",
            failure: Failure::Stops {
                events: 0,
                ending: Ending::Exit(101),
                diagnostic: "fs/open_tree: cannot continue: glibc's open_tree resolves",
            },
        },
    ],
    ..DEFAULTS
};
