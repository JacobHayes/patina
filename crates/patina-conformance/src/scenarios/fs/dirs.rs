//! fs/dirs — mkdirat / renameat / unlinkat: the namespace mutations and their
//! errno vocabulary (existence checked through newfstatat).

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

fn exists(p: &Probe, path: &str) -> bool {
    p.newfstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW).0 == 0
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let d = format!("{root}/d");
    let f = format!("{root}/f");
    let g = format!("{root}/g");
    let d2 = format!("{root}/d2");

    p.check(
        "mkdirat creates a directory",
        p.mkdirat(AT_FDCWD, &d, 0o750) == 0,
    );
    p.check(
        "mkdirat on an existing name is EEXIST",
        p.mkdirat(AT_FDCWD, &d, 0o750) == neg(EEXIST),
    );
    p.check(
        "mkdirat under a missing parent is ENOENT",
        p.mkdirat(AT_FDCWD, &format!("{root}/missing/x"), 0o750) == neg(ENOENT),
    );
    let fd = p.openat(AT_FDCWD, &f, O_WRONLY | O_CREAT | O_EXCL, 0o640);
    p.require("create f", fd >= 0);
    p.write(fd, b"f");
    p.check(
        "mkdirat under a file is ENOTDIR",
        p.mkdirat(AT_FDCWD, &format!("{f}/x"), 0o750) == neg(ENOTDIR),
    );
    p.check(
        "mkdirat with a trailing slash",
        p.mkdirat(AT_FDCWD, &format!("{d2}/"), 0o750) == 0,
    );
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open root", dirfd >= 0);
    p.check(
        "mkdirat relative to a dirfd",
        p.mkdirat(dirfd, "sub", 0o750) == 0,
    );
    p.check(
        "the relative directory exists by absolute path",
        exists(p, &format!("{root}/sub")),
    );

    p.check(
        "renameat f -> g",
        p.renameat(AT_FDCWD, &f, AT_FDCWD, &g) == 0,
    );
    p.check("the old name is gone", !exists(p, &f));
    let (r, moved) = p.newfstatat(AT_FDCWD, &g, 0);
    p.check(
        "the new name carries the data",
        r == 0 && moved.as_ref().is_some_and(|s| s.size == 1),
    );
    p.check(
        "renameat of a missing name is ENOENT",
        p.renameat(AT_FDCWD, &f, AT_FDCWD, &g) == neg(ENOENT),
    );
    p.check(
        "renameat file onto a directory is EISDIR",
        p.renameat(AT_FDCWD, &g, AT_FDCWD, &d) == neg(EISDIR),
    );
    p.check(
        "renameat directory onto a file is ENOTDIR",
        p.renameat(AT_FDCWD, &d, AT_FDCWD, &g) == neg(ENOTDIR),
    );
    let inner = p.openat(
        AT_FDCWD,
        &format!("{d2}/inner"),
        O_WRONLY | O_CREAT | O_EXCL,
        0o640,
    );
    p.require("create d2/inner", inner >= 0);
    p.close(inner);
    let onto_nonempty = p.renameat(AT_FDCWD, &d, AT_FDCWD, &d2);
    p.check(
        "renameat directory onto a non-empty directory is ENOTEMPTY",
        onto_nonempty == neg(ENOTEMPTY) || onto_nonempty == neg(EEXIST),
    );
    p.check(
        "renameat a directory into itself is EINVAL",
        p.renameat(AT_FDCWD, &d, AT_FDCWD, &format!("{d}/inside")) == neg(EINVAL),
    );
    p.check(
        "renameat onto the same name is a no-op success",
        p.renameat(AT_FDCWD, &g, AT_FDCWD, &g) == 0,
    );
    p.check(
        "renameat between dirfd-relative names",
        p.renameat(dirfd, "g", dirfd, "sub/g2") == 0,
    );
    p.check(
        "the moved file exists at its new relative name",
        exists(p, &format!("{root}/sub/g2")),
    );
    p.check(
        "renameat directory onto an empty directory",
        p.renameat(AT_FDCWD, &d, AT_FDCWD, &format!("{root}/sub/dmoved")) == 0,
    );

    p.check(
        "unlinkat on a directory without AT_REMOVEDIR is EISDIR",
        p.unlinkat(AT_FDCWD, &d2, 0) == neg(EISDIR),
    );
    p.check(
        "unlinkat AT_REMOVEDIR on a non-empty directory is ENOTEMPTY",
        p.unlinkat(AT_FDCWD, &d2, AT_REMOVEDIR) == neg(ENOTEMPTY),
    );
    p.check(
        "unlinkat removes a file",
        p.unlinkat(AT_FDCWD, &format!("{d2}/inner"), 0) == 0,
    );
    p.check(
        "unlinkat AT_REMOVEDIR on an empty directory",
        p.unlinkat(AT_FDCWD, &d2, AT_REMOVEDIR) == 0,
    );
    p.check(
        "unlinkat of a missing name is ENOENT",
        p.unlinkat(AT_FDCWD, &d2, 0) == neg(ENOENT),
    );
    p.check(
        "unlinkat with an unknown flag is EINVAL",
        p.unlinkat(AT_FDCWD, &g, 0x1) == neg(EINVAL),
    );
    p.check(
        "unlinkat AT_REMOVEDIR on a file is ENOTDIR",
        p.unlinkat(dirfd, "sub/g2", AT_REMOVEDIR) == neg(ENOTDIR),
    );

    let open_then_unlink = p.openat(dirfd, "sub/g2", O_RDWR, 0);
    p.require("open sub/g2", open_then_unlink >= 0);
    p.check(
        "unlinkat relative to a dirfd",
        p.unlinkat(dirfd, "sub/g2", 0) == 0,
    );
    let (r, gone) = p.fstat(open_then_unlink);
    p.check(
        "an unlinked open file still answers fstat with nlink 0",
        r == 0 && gone.as_ref().is_some_and(|s| s.nlink == 0),
    );
    p.check(
        "and still accepts writes",
        p.write(open_then_unlink, b"still") == 5,
    );
    p.check(
        "but its name is gone",
        !exists(p, &format!("{root}/sub/g2")),
    );
    p.close(open_then_unlink);
    p.check(
        "unlinkat AT_REMOVEDIR relative to a dirfd",
        p.unlinkat(dirfd, "sub/dmoved", AT_REMOVEDIR) == 0,
    );
    p.check(
        "unlinkat AT_REMOVEDIR on the now-empty sub",
        p.unlinkat(dirfd, "sub", AT_REMOVEDIR) == 0,
    );
    p.close(fd);
    p.close(dirfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/dirs",
    run,
    covers: &[
        Syscall::N_mkdirat,
        Syscall::N_renameat,
        Syscall::N_unlinkat,
        Syscall::N_newfstatat,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_fstat,
        Syscall::N_close,
    ],
    symbols: &[
        "mkdirat", "renameat", "unlinkat", "fstatat", "openat", "write", "fstat", "close",
    ],
    ..DEFAULTS
};
