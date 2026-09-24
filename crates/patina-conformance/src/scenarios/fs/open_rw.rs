//! fs/open_rw — openat / read / write / lseek / close: the descriptor cursor,
//! access modes, creation flags, and the errno vocabulary around them.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/data");

    let fd = p.openat(
        AT_FDCWD,
        &file,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
        0o644,
    );
    p.require("create the data file", fd >= 0);
    p.check(
        "write returns the full length",
        p.write(fd, b"hello world") == 11,
    );
    p.check(
        "SEEK_CUR after the write is at the end",
        p.lseek(fd, 0, SEEK_CUR) == 11,
    );
    p.check("read at EOF returns 0", p.read(fd, 8).0 == 0);
    p.check("SEEK_SET rewinds", p.lseek(fd, 0, SEEK_SET) == 0);
    let (n, data) = p.read(fd, 5);
    p.check(
        "a partial read returns the prefix",
        n == 5 && data == b"hello",
    );
    p.check(
        "SEEK_CUR advanced by the read",
        p.lseek(fd, 0, SEEK_CUR) == 5,
    );
    p.check("SEEK_END reports the size", p.lseek(fd, 0, SEEK_END) == 11);
    p.check(
        "seeking past EOF succeeds",
        p.lseek(fd, 100, SEEK_SET) == 100,
    );
    p.check("a write past EOF extends the file", p.write(fd, b"!") == 1);
    p.check("size after the hole write", p.lseek(fd, 0, SEEK_END) == 101);
    p.lseek(fd, 50, SEEK_SET);
    let (n, data) = p.read(fd, 4);
    p.check("the hole reads as zeros", n == 4 && data == [0, 0, 0, 0]);
    p.check(
        "a negative offset is EINVAL",
        p.lseek(fd, -1, SEEK_SET) == neg(EINVAL),
    );
    p.check("a bad whence is EINVAL", p.lseek(fd, 0, 99) == neg(EINVAL));
    p.check("a zero-length read returns 0", p.read(fd, 0).0 == 0);
    p.check("a zero-length write returns 0", p.write(fd, b"") == 0);

    let again = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.check(
        "O_EXCL on an existing file is EEXIST",
        i64::from(again) == neg(EEXIST),
    );
    let missing = p.openat(AT_FDCWD, &format!("{root}/missing"), O_RDONLY, 0);
    p.check(
        "a missing file is ENOENT",
        i64::from(missing) == neg(ENOENT),
    );

    let ro = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("read-only open", ro >= 0);
    p.check(
        "write on O_RDONLY is EBADF",
        p.write(ro, b"x") == neg(EBADF),
    );
    let (n, data) = p.read(ro, 5);
    p.check(
        "a second open has its own cursor",
        n == 5 && data == b"hello",
    );
    let wo = p.openat(AT_FDCWD, &file, O_WRONLY, 0);
    p.require("write-only open", wo >= 0);
    p.check("read on O_WRONLY is EBADF", p.read(wo, 1).0 == neg(EBADF));
    let ap = p.openat(AT_FDCWD, &file, O_WRONLY | O_APPEND, 0);
    p.require("append open", ap >= 0);
    p.check(
        "O_APPEND write lands at the end",
        p.write(ap, b"++") == 2 && p.lseek(ap, 0, SEEK_CUR) == 103,
    );
    let tr = p.openat(AT_FDCWD, &file, O_RDWR | O_TRUNC, 0);
    p.require("truncating open", tr >= 0);
    p.check("O_TRUNC empties the file", p.lseek(tr, 0, SEEK_END) == 0);
    p.check(
        "the truncation is visible through the older descriptor",
        p.lseek(fd, 0, SEEK_END) == 0,
    );

    let on_file = p.openat(AT_FDCWD, &file, O_RDONLY | O_DIRECTORY, 0);
    p.check(
        "O_DIRECTORY on a file is ENOTDIR",
        i64::from(on_file) == neg(ENOTDIR),
    );
    let through = p.openat(AT_FDCWD, &format!("{file}/x"), O_RDONLY, 0);
    p.check(
        "a component through a file is ENOTDIR",
        i64::from(through) == neg(ENOTDIR),
    );
    let trailing = p.openat(AT_FDCWD, &format!("{file}/"), O_RDONLY, 0);
    p.check(
        "a trailing slash on a file is ENOTDIR",
        i64::from(trailing) == neg(ENOTDIR),
    );
    // An unexpected success is closed unobserved so the descriptor ordinals
    // downstream stay aligned with the native run.
    if trailing >= 0 {
        p.rec.quiet(|| p.close(trailing));
    }

    let dir = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("directory open", dir >= 0);
    p.check(
        "read on a directory is EISDIR",
        p.read(dir, 8).0 == neg(EISDIR),
    );
    p.check(
        "write on a directory is EBADF",
        p.write(dir, b"x") == neg(EBADF),
    );
    let rel = p.openat(dir, "relative", O_WRONLY | O_CREAT, 0o600);
    p.check(
        "openat creates relative to a directory descriptor",
        rel >= 0,
    );
    let via_path = p.openat(AT_FDCWD, &format!("{root}/relative"), O_RDONLY, 0);
    p.check(
        "the relative name is visible by absolute path",
        via_path >= 0,
    );
    let bad_dirfd = p.openat(fd, "x", O_RDONLY | O_CREAT, 0o600);
    p.check(
        "a dirfd that is a file is ENOTDIR",
        i64::from(bad_dirfd) == neg(ENOTDIR),
    );
    let closed_dirfd = p.openat(4000, "x", O_RDONLY, 0);
    p.check(
        "a dirfd that is not open is EBADF",
        i64::from(closed_dirfd) == neg(EBADF),
    );
    let empty = p.openat(AT_FDCWD, "", O_RDONLY, 0);
    p.check("an empty path is ENOENT", i64::from(empty) == neg(ENOENT));
    if empty >= 0 {
        p.rec.quiet(|| p.close(empty));
    }

    p.check("close succeeds", p.close(fd) == 0);
    p.check("a second close is EBADF", p.close(fd) == neg(EBADF));
    p.check(
        "read on a closed descriptor is EBADF",
        p.read(fd, 1).0 == neg(EBADF),
    );
    p.check(
        "lseek on a closed descriptor is EBADF",
        p.lseek(fd, 0, SEEK_SET) == neg(EBADF),
    );
    p.check(
        "close of a never-open descriptor is EBADF",
        p.close(4000) == neg(EBADF),
    );
    let reused = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.check("the lowest free descriptor number is reused", reused == fd);

    for f in [ro, wo, ap, tr, dir, rel, via_path, reused] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/open_rw",
    run,
    covers: &[
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_lseek,
        Syscall::N_close,
    ],
    symbols: &["openat", "read", "write", "lseek", "close"],
    ..DEFAULTS
};
