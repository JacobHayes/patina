//! fs/links — symlinkat / readlinkat / linkat: link targets and truncation,
//! dangling links, hard-link counts, and AT_SYMLINK_FOLLOW.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    let f = format!("{root}/f");
    let l = format!("{root}/l");
    let fd = p.openat(AT_FDCWD, &f, O_WRONLY | O_CREAT | O_EXCL, 0o640);
    p.require("create f", fd >= 0);
    p.write(fd, b"abc");
    p.close(fd);
    let (_, f_stat) = p.newfstatat(AT_FDCWD, &f, 0);
    let f_ino = f_stat.expect("stat f").ino;

    p.check(
        "symlinkat creates a link",
        p.symlinkat("target-name", AT_FDCWD, &l) == 0,
    );
    p.check(
        "symlinkat onto an existing name is EEXIST",
        p.symlinkat("f", AT_FDCWD, &l) == neg(EEXIST),
    );
    let (r, target) = p.readlinkat(AT_FDCWD, &l, 64);
    p.check(
        "readlinkat returns the target bytes",
        r == 11 && target == "target-name",
    );
    let (r, truncated) = p.readlinkat(AT_FDCWD, &l, 4);
    p.check(
        "readlinkat truncates to bufsize",
        r == 4 && truncated == "targ",
    );
    let (r, _) = p.readlinkat(AT_FDCWD, &l, 0);
    p.check("readlinkat with bufsize 0 is EINVAL", r == neg(EINVAL));
    let (r, _) = p.readlinkat(AT_FDCWD, &f, 64);
    p.check("readlinkat on a regular file is EINVAL", r == neg(EINVAL));
    let (r, _) = p.readlinkat(AT_FDCWD, &format!("{root}/missing"), 64);
    p.check("readlinkat on a missing name is ENOENT", r == neg(ENOENT));
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open root", dirfd >= 0);
    let (r, relative) = p.readlinkat(dirfd, "l", 64);
    p.check(
        "readlinkat relative to a dirfd",
        r == 11 && relative == "target-name",
    );
    let (r, _) = p.newfstatat(AT_FDCWD, &l, 0);
    p.check("following a dangling link is ENOENT", r == neg(ENOENT));
    let (r, lstat) = p.newfstatat(AT_FDCWD, &l, AT_SYMLINK_NOFOLLOW);
    p.check(
        "the dangling link itself stats as lnk with the target length",
        r == 0
            && lstat
                .as_ref()
                .is_some_and(|s| s.kind == "lnk" && s.size == 11),
    );
    p.check(
        "symlinkat with an empty target is ENOENT",
        p.symlinkat("", AT_FDCWD, &format!("{root}/empty")) == neg(ENOENT),
    );
    p.check(
        "symlinkat relative to a dirfd",
        p.symlinkat("f", dirfd, "lf") == 0,
    );
    let (r, via) = p.newfstatat(dirfd, "lf", 0);
    p.check(
        "the relative link resolves to f",
        r == 0 && via.as_ref().is_some_and(|s| s.ino == f_ino),
    );

    p.check(
        "linkat f -> h",
        p.linkat(AT_FDCWD, &f, AT_FDCWD, &format!("{root}/h"), 0) == 0,
    );
    let (_, after) = p.newfstatat(AT_FDCWD, &f, 0);
    p.check(
        "a hard link bumps nlink to 2",
        after.as_ref().is_some_and(|s| s.nlink == 2),
    );
    let (_, h) = p.newfstatat(AT_FDCWD, &format!("{root}/h"), 0);
    p.check(
        "the new name is the same inode",
        h.as_ref().is_some_and(|s| s.ino == f_ino),
    );
    p.check(
        "linkat onto an existing name is EEXIST",
        p.linkat(AT_FDCWD, &format!("{root}/h"), AT_FDCWD, &f, 0) == neg(EEXIST),
    );
    p.check(
        "linkat of a missing source is ENOENT",
        p.linkat(
            AT_FDCWD,
            &format!("{root}/missing"),
            AT_FDCWD,
            &format!("{root}/m"),
            0,
        ) == neg(ENOENT),
    );
    p.check(
        "mkdirat d",
        p.mkdirat(AT_FDCWD, &format!("{root}/d"), 0o750) == 0,
    );
    p.check(
        "linkat of a directory is EPERM",
        p.linkat(
            AT_FDCWD,
            &format!("{root}/d"),
            AT_FDCWD,
            &format!("{root}/d2"),
            0,
        ) == neg(EPERM),
    );
    p.check(
        "linkat of a symlink without AT_SYMLINK_FOLLOW links the link",
        p.linkat(dirfd, "lf", dirfd, "lf2", 0) == 0,
    );
    let (r, lf2) = p.newfstatat(dirfd, "lf2", AT_SYMLINK_NOFOLLOW);
    p.check(
        "the linked link is itself a symlink",
        r == 0 && lf2.as_ref().is_some_and(|s| s.kind == "lnk"),
    );
    p.check(
        "linkat with AT_SYMLINK_FOLLOW links the target",
        p.linkat(dirfd, "lf", dirfd, "lf3", AT_SYMLINK_FOLLOW) == 0,
    );
    let (r, lf3) = p.newfstatat(dirfd, "lf3", AT_SYMLINK_NOFOLLOW);
    p.check(
        "the followed link is f's inode with nlink 3",
        r == 0
            && lf3
                .as_ref()
                .is_some_and(|s| s.kind == "reg" && s.ino == f_ino && s.nlink == 3),
    );
    p.check(
        "linkat with an unknown flag is EINVAL",
        p.linkat(dirfd, "f", dirfd, "bad", 0x1) == neg(EINVAL),
    );
    p.check(
        "unlinkat h",
        p.unlinkat(AT_FDCWD, &format!("{root}/h"), 0) == 0,
    );
    let (_, dropped) = p.newfstatat(AT_FDCWD, &f, 0);
    p.check(
        "unlinking one name drops nlink to 2",
        dropped.as_ref().is_some_and(|s| s.nlink == 2),
    );
    p.close(dirfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/links",
    run,
    covers: &[
        Syscall::N_symlinkat,
        Syscall::N_readlinkat,
        Syscall::N_linkat,
        Syscall::N_newfstatat,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_mkdirat,
        Syscall::N_unlinkat,
    ],
    symbols: &[
        "symlinkat",
        "readlinkat",
        "linkat",
        "fstatat",
        "openat",
        "write",
        "close",
        "mkdirat",
        "unlinkat",
    ],
    ..DEFAULTS
};
