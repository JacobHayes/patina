//! fs/xattr — the extended-attribute rows (setxattr(2), getxattr(2),
//! listxattr(2), removexattr(2), xattr(7); fs/xattr.c): by path (followed),
//! by link (`l*`) and by descriptor (`f*`). Values round-trip, a zero size
//! asks for the length, a short buffer is ERANGE, a missing name ENODATA;
//! XATTR_CREATE on an existing name is EEXIST and XATTR_REPLACE on a missing
//! one ENODATA (both together: each where it applies), an unknown flag EINVAL; a name without a
//! namespace is EOPNOTSUPP, an empty or over-long name ERANGE, a value over
//! XATTR_SIZE_MAX E2BIG before the value is read (a NULL value of that size is
//! still E2BIG; of a small size, EFAULT). The set and remove path rows judge
//! the flags, the name and the size before the path (a NULL or missing path
//! with an empty name is ERANGE); get and list look the path up first. Permissions are the inode's
//! (xattr_permission): `user.*` needs a regular file or directory — on a
//! symlink or a FIFO a write is EPERM and a read ENODATA — plus the mode's
//! r/w bits (EACCES), and `trusted.*` needs CAP_SYS_ADMIN (EPERM to set,
//! ENODATA to read). The `f*` rows need no access mode but refuse O_PATH
//! (EBADF). Needs `user.*` attributes on the run directory's filesystem.
//!
//! The libc vehicle goes through glibc's `setxattr`, `getxattr`,
//! `fgetxattr`, `listxattr` and `removexattr`, which the shim does not define
//! (registry `Absent`): it reaches them through `dlsym`
//! (`vehicle::WRAPPERS`). glibc's other xattr wrappers have no registry row
//! yet, so no scenario can name them: the libc vehicle spells their rows
//! `syscall(2)`.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, XattrTarget, neg};
use libc::*;

/// linux/limits.h XATTR_SIZE_MAX.
const XATTR_SIZE_MAX: usize = 65536;

/// A flag bit the set rows do not define.
const UNKNOWN_XATTR_FLAG: i32 = 4;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let dir = format!("{root}/d");
    let link = format!("{root}/l");
    let fifo = format!("{root}/p");
    let readonly = format!("{root}/ro");
    let writeonly = format!("{root}/wo");
    p.create(&file, 0o644);
    p.check("mkdirat d", p.mkdirat(AT_FDCWD, &dir, 0o755) == 0);
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    p.check(
        "mknodat p",
        p.mknodat(AT_FDCWD, &fifo, S_IFIFO | 0o644, 0) == 0,
    );
    p.create(&readonly, 0o444);
    p.create(&writeonly, 0o200);
    let f = XattrTarget::Path(&file);

    // ---- set, get, list, remove by path ------------------------------------
    let (r, names) = p.listxattr(f, 256);
    p.check("a fresh file lists nothing", r == 0 && names.is_empty());
    p.check(
        "setxattr user.a",
        p.setxattr(f, "user.a", Some(b"v1"), 2, 0) == 0,
    );
    p.check(
        "a zero size asks for the value's length",
        p.getxattr(f, "user.a", 0).0 == 2,
    );
    let (r, value) = p.getxattr(f, "user.a", 64);
    p.check("getxattr returns the value", r == 2 && value == b"v1");
    p.check(
        "a buffer shorter than the value is ERANGE",
        p.getxattr(f, "user.a", 1).0 == neg(ERANGE),
    );
    p.check(
        "a missing name is ENODATA",
        p.getxattr(f, "user.missing", 64).0 == neg(ENODATA),
    );
    p.check(
        "XATTR_CREATE on an existing name is EEXIST",
        p.setxattr(f, "user.a", Some(b"v2"), 2, XATTR_CREATE) == neg(EEXIST),
    );
    p.check(
        "XATTR_REPLACE on a missing name is ENODATA",
        p.setxattr(f, "user.b", Some(b"v2"), 2, XATTR_REPLACE) == neg(ENODATA),
    );
    p.check(
        "XATTR_CREATE|XATTR_REPLACE is accepted: on an existing name CREATE is EEXIST",
        p.setxattr(f, "user.a", Some(b"v2"), 2, XATTR_CREATE | XATTR_REPLACE) == neg(EEXIST),
    );
    p.check(
        "and on a missing name REPLACE is ENODATA",
        p.setxattr(f, "user.b", Some(b"v2"), 2, XATTR_CREATE | XATTR_REPLACE) == neg(ENODATA),
    );
    p.check(
        "an unknown flag is EINVAL",
        p.setxattr(f, "user.a", Some(b"v2"), 2, UNKNOWN_XATTR_FLAG) == neg(EINVAL),
    );
    p.check(
        "XATTR_REPLACE on an existing name",
        p.setxattr(f, "user.a", Some(b"v2"), 2, XATTR_REPLACE) == 0,
    );
    p.check(
        "the value was replaced",
        p.getxattr(f, "user.a", 64).1 == b"v2",
    );
    let set = p.setxattr(f, "user.empty", Some(b""), 0, XATTR_CREATE);
    let (got, _) = p.getxattr(f, "user.empty", 64);
    p.check("an empty value is a value", set == 0 && got == 0);
    p.check(
        "a name without a namespace is EOPNOTSUPP",
        p.setxattr(f, "plain", Some(b"v"), 1, 0) == neg(EOPNOTSUPP),
    );
    p.check(
        "an empty name is ERANGE",
        p.setxattr(f, "", Some(b"v"), 1, 0) == neg(ERANGE),
    );
    let long = format!("user.{}", "n".repeat(251));
    p.check(
        "a 256-byte name is ERANGE",
        p.setxattr(f, &long, Some(b"v"), 1, 0) == neg(ERANGE),
    );
    p.check(
        "a value over XATTR_SIZE_MAX is E2BIG before the value is read",
        p.setxattr(f, "user.big", None, XATTR_SIZE_MAX + 1, 0) == neg(E2BIG),
    );
    p.check(
        "a NULL value of a small size is EFAULT",
        p.setxattr(f, "user.null", None, 2, 0) == neg(EFAULT),
    );
    p.check(
        "trusted.* without CAP_SYS_ADMIN is EPERM to set",
        p.setxattr(f, "trusted.x", Some(b"v"), 1, 0) == neg(EPERM),
    );
    p.check(
        "and ENODATA to read",
        p.getxattr(f, "trusted.x", 64).0 == neg(ENODATA),
    );
    let (r, names) = p.listxattr(f, 0);
    p.check(
        "a zero size asks for the listing's length",
        r == ("user.a\0".len() + "user.empty\0".len()) as i64 && names.is_empty(),
    );
    p.check(
        "a listing buffer too short is ERANGE",
        p.listxattr(f, 5).0 == neg(ERANGE),
    );
    let (r, names) = p.listxattr(f, 256);
    p.check(
        "listxattr names every attribute",
        r == 18 && names == ["user.a", "user.empty"],
    );
    p.check(
        "removexattr user.empty",
        p.removexattr(f, "user.empty") == 0,
    );
    p.check(
        "a removed name is ENODATA",
        p.removexattr(f, "user.empty") == neg(ENODATA),
    );
    p.check(
        "getxattr of a missing path is ENOENT",
        p.getxattr(XattrTarget::Path(&format!("{root}/missing")), "user.a", 64)
            .0
            == neg(ENOENT),
    );
    p.check(
        "getxattr through a file is ENOTDIR",
        p.getxattr(XattrTarget::Path(&format!("{file}/x")), "user.a", 64)
            .0
            == neg(ENOTDIR),
    );

    // ---- links, FIFOs, directories -------------------------------------------
    let l = XattrTarget::Link(&link);
    p.check(
        "lsetxattr user.* on a symlink is EPERM",
        p.setxattr(l, "user.a", Some(b"v"), 1, 0) == neg(EPERM),
    );
    p.check(
        "lgetxattr user.* on a symlink is ENODATA",
        p.getxattr(l, "user.a", 64).0 == neg(ENODATA),
    );
    let (r, names) = p.listxattr(l, 256);
    p.check(
        "llistxattr of a symlink lists nothing",
        r == 0 && names.is_empty(),
    );
    p.check(
        "lremovexattr user.* on a symlink is EPERM",
        p.removexattr(l, "user.a") == neg(EPERM),
    );
    let (r, value) = p.getxattr(XattrTarget::Path(&link), "user.a", 64);
    p.check("getxattr follows a symlink", r == 2 && value == b"v2");
    let set = p.setxattr(XattrTarget::Path(&link), "user.via", Some(b"L"), 1, 0);
    let (_, value) = p.getxattr(f, "user.via", 64);
    p.check(
        "setxattr through a symlink sets the target's",
        set == 0 && value == b"L",
    );
    let (r, names) = p.listxattr(XattrTarget::Link(&file), 256);
    p.check(
        "llistxattr of a regular file lists it",
        r > 0 && names == ["user.a", "user.via"],
    );
    let fifo_target = XattrTarget::Path(&fifo);
    p.check(
        "setxattr user.* on a FIFO is EPERM",
        p.setxattr(fifo_target, "user.a", Some(b"v"), 1, 0) == neg(EPERM),
    );
    p.check(
        "getxattr user.* on a FIFO is ENODATA",
        p.getxattr(fifo_target, "user.a", 64).0 == neg(ENODATA),
    );
    let d = XattrTarget::Path(&dir);
    p.check(
        "setxattr user.* on a directory",
        p.setxattr(d, "user.d", Some(b"dir"), 3, 0) == 0,
    );
    p.check(
        "a directory lists its attribute",
        p.listxattr(d, 256).1 == ["user.d"],
    );

    // ---- the mode's bits ---------------------------------------------------
    p.check(
        "setxattr on a file without w is EACCES",
        p.setxattr(XattrTarget::Path(&readonly), "user.a", Some(b"v"), 1, 0) == neg(EACCES),
    );
    p.check(
        "getxattr on a file with r is ENODATA for a missing name",
        p.getxattr(XattrTarget::Path(&readonly), "user.a", 64).0 == neg(ENODATA),
    );
    p.check(
        "getxattr on a file without r is EACCES",
        p.getxattr(XattrTarget::Path(&writeonly), "user.a", 64).0 == neg(EACCES),
    );
    p.check(
        "setxattr on a file with w only",
        p.setxattr(XattrTarget::Path(&writeonly), "user.a", Some(b"w"), 1, 0) == 0,
    );

    // ---- by descriptor -----------------------------------------------------
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("open f read-only", reader >= 0);
    let by_fd = XattrTarget::Fd(reader);
    p.check(
        "fsetxattr through an O_RDONLY descriptor",
        p.setxattr(by_fd, "user.fd", Some(b"F"), 1, 0) == 0,
    );
    let (r, value) = p.getxattr(by_fd, "user.fd", 64);
    p.check("fgetxattr reads it back", r == 1 && value == b"F");
    p.check(
        "flistxattr lists it",
        p.listxattr(by_fd, 256).1 == ["user.a", "user.fd", "user.via"],
    );
    p.check(
        "fremovexattr removes it",
        p.removexattr(by_fd, "user.fd") == 0,
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open f O_PATH", location >= 0);
    let path_fd = XattrTarget::Fd(location);
    p.check(
        "fsetxattr on O_PATH is EBADF",
        p.setxattr(path_fd, "user.x", Some(b"x"), 1, 0) == neg(EBADF),
    );
    p.check(
        "fgetxattr on O_PATH is EBADF",
        p.getxattr(path_fd, "user.a", 64).0 == neg(EBADF),
    );
    p.check(
        "flistxattr on O_PATH is EBADF",
        p.listxattr(path_fd, 256).0 == neg(EBADF),
    );
    p.check(
        "fremovexattr on O_PATH is EBADF",
        p.removexattr(path_fd, "user.a") == neg(EBADF),
    );
    p.check(
        "fgetxattr on a closed descriptor is EBADF",
        p.getxattr(XattrTarget::Fd(4000), "user.a", 64).0 == neg(EBADF),
    );

    // ---- attributes belong to the inode --------------------------------------
    let hard = format!("{root}/h");
    p.check(
        "linkat f -> h",
        p.linkat(AT_FDCWD, &file, AT_FDCWD, &hard, 0) == 0,
    );
    p.check(
        "a hard link shares the attributes",
        p.getxattr(XattrTarget::Path(&hard), "user.a", 64).1 == b"v2",
    );
    let renamed = format!("{root}/moved");
    p.check(
        "renameat f -> moved",
        p.renameat(AT_FDCWD, &file, AT_FDCWD, &renamed) == 0,
    );
    p.check(
        "attributes survive a rename",
        p.getxattr(XattrTarget::Path(&renamed), "user.a", 64).1 == b"v2",
    );

    // ---- the path rows' order --------------------------------------------------
    // set and remove judge the flags, the name and the size before they look
    // the path up (fs/xattr.c path_setxattr, path_removexattr); get and list
    // look it up first.
    let missing = format!("{root}/missing/x");
    p.check(
        "setxattr of a NULL path with an empty name is ERANGE",
        p.setxattr(XattrTarget::NullPath, "", Some(b"v"), 1, 0) == neg(ERANGE),
    );
    p.check(
        "with an oversized value E2BIG",
        p.setxattr(XattrTarget::NullPath, "user.a", None, XATTR_SIZE_MAX + 1, 0) == neg(E2BIG),
    );
    p.check(
        "with an unknown flag EINVAL",
        p.setxattr(
            XattrTarget::NullPath,
            "user.a",
            Some(b"v"),
            1,
            UNKNOWN_XATTR_FLAG,
        ) == neg(EINVAL),
    );
    p.check(
        "and with a good name EFAULT",
        p.setxattr(XattrTarget::NullPath, "user.a", Some(b"v"), 1, 0) == neg(EFAULT),
    );
    p.check(
        "removexattr of a NULL path with an empty name is ERANGE",
        p.removexattr(XattrTarget::NullPath, "") == neg(ERANGE),
    );
    p.check(
        "of a missing path too",
        p.removexattr(XattrTarget::Path(&missing), "") == neg(ERANGE),
    );
    p.check(
        "and of a NULL path with a good name EFAULT",
        p.removexattr(XattrTarget::NullPath, "user.a") == neg(EFAULT),
    );
    p.check(
        "getxattr of a NULL path is EFAULT whatever the name",
        p.getxattr(XattrTarget::NullPath, "", 64).0 == neg(EFAULT),
    );
    p.check(
        "and listxattr of one",
        p.listxattr(XattrTarget::NullPath, 64).0 == neg(EFAULT),
    );
    p.close(reader);
    p.close(location);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/xattr",
    run,
    covers: &[
        Syscall::N_setxattr,
        Syscall::N_lsetxattr,
        Syscall::N_fsetxattr,
        Syscall::N_getxattr,
        Syscall::N_lgetxattr,
        Syscall::N_fgetxattr,
        Syscall::N_listxattr,
        Syscall::N_llistxattr,
        Syscall::N_flistxattr,
        Syscall::N_removexattr,
        Syscall::N_lremovexattr,
        Syscall::N_fremovexattr,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_mknodat,
        Syscall::N_linkat,
        Syscall::N_renameat,
    ],
    symbols: &[
        "setxattr",
        "getxattr",
        "fgetxattr",
        "listxattr",
        "removexattr",
        "syscall",
        "openat",
        "close",
        "mkdirat",
        "symlinkat",
        "mknodat",
        "linkat",
        "renameat",
    ],
    resolves: &[
        "setxattr",
        "getxattr",
        "fgetxattr",
        "listxattr",
        "removexattr",
    ],
    needs: &[Need::UserXattrs, Need::Unprivileged],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: &[Vehicle::Libc],
        what: "the shim defines none of setxattr/getxattr/fgetxattr/listxattr/removexattr (registry `Absent`): a guest importing one is refused by the pre-run audit, and `dlsym` finds none (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the libc leg stops at its first call",
        failure: Failure::Stops {
            events: 12,
            ending: Ending::Exit(101),
            diagnostic: "fs/xattr: cannot continue: glibc's listxattr resolves",
        },
    }],
    ..DEFAULTS
};
