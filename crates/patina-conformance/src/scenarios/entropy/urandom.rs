//! entropy/urandom — the entropy device as a node (drivers/char/mem.c's
//! `urandom`, a devtmpfs node), by path and by descriptor:
//!
//! * `/dev/urandom` is a root-owned `0666` character device (1:9) with one
//!   link and no size, and a descriptor of it names the same node;
//! * the caller may read and write it but not execute it (`access`); changing
//!   its mode is `EPERM` (not the owner), truncating it `EINVAL` (no regular
//!   file), removing it `EACCES` (`/dev` is root's), making a directory over
//!   it `EEXIST`, and reading it as a link `EINVAL`;
//! * an open refuses `O_CREAT|O_EXCL` (`EEXIST`) and `O_DIRECTORY`
//!   (`ENOTDIR`); a read-only one opens it, `O_CREAT`, `O_TRUNC` and
//!   `O_APPEND` included; its descriptor seeks nowhere (`noop_llseek`: 0).
//!
//! Nothing here writes to the device or changes it.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

const URANDOM: &str = "/dev/urandom";

/// Opens of the device and their answers (0: a descriptor).
const OPENS: [(c_int, c_int); 6] = [
    (O_RDONLY, 0),
    (O_RDONLY | O_TRUNC, 0),
    (O_RDONLY | O_CREAT, 0),
    (O_RDONLY | O_APPEND, 0),
    (O_RDONLY | O_CREAT | O_EXCL, EEXIST),
    (O_RDONLY | O_DIRECTORY, ENOTDIR),
];

pub fn run(p: &Probe) {
    let (r, node) = p.newfstatat(AT_FDCWD, URANDOM, 0);
    p.check(
        "it is a root-owned 0666 character device with one link and no size",
        r == 0
            && node.as_ref().is_some_and(|node| {
                node.kind == "chr"
                    && node.perm == 0o666
                    && node.uid == 0
                    && node.nlink == 1
                    && node.size == 0
            }),
    );
    // SAFETY: plain data.
    let mut raw: stat = unsafe { std::mem::zeroed() };
    let path = c"/dev/urandom";
    let r = p.call_observed(
        Syscall::N_newfstatat,
        [
            AT_FDCWD as i64,
            path.as_ptr() as i64,
            &mut raw as *mut stat as i64,
            0,
            0,
            0,
        ],
    );
    p.check(
        "its device is 1:9",
        r == 0 && major(raw.st_rdev) == 1 && minor(raw.st_rdev) == 9,
    );
    let fd = p.openat(AT_FDCWD, URANDOM, O_RDONLY | O_CLOEXEC, 0);
    p.require("open the entropy device", fd >= 0);
    let (_, opened) = p.fstat(fd);
    p.check(
        "a descriptor of it names the same node",
        opened
            .zip(node)
            .is_some_and(|(opened, node)| opened.ino == node.ino && opened.kind == "chr"),
    );
    p.check("it seeks nowhere", p.lseek(fd, 5, SEEK_SET) == 0);
    p.check(
        "fchmod of it is EPERM (not the owner)",
        p.fchmod(fd, 0o600) == neg(EPERM),
    );
    p.close(fd);

    for (mode, answer, label) in [
        (F_OK, 0, "it exists"),
        (R_OK | W_OK, 0, "the caller may read and write it"),
        (X_OK, EACCES, "but not execute it"),
    ] {
        p.check(
            label,
            p.faccessat(AT_FDCWD, URANDOM, mode, 0, false)
                == if answer == 0 { 0 } else { neg(answer) },
        );
    }
    p.check(
        "changing its mode is EPERM",
        p.fchmodat(AT_FDCWD, URANDOM, 0o666) == neg(EPERM),
    );
    p.check(
        "truncating it is EINVAL",
        p.truncate(URANDOM, 0) == neg(EINVAL),
    );
    p.check(
        "removing it is EACCES",
        p.unlinkat(AT_FDCWD, URANDOM, 0) == neg(EACCES),
    );
    p.check(
        "a directory over it is EEXIST",
        p.mkdirat(AT_FDCWD, URANDOM, 0o755) == neg(EEXIST),
    );
    p.check(
        "reading it as a link is EINVAL",
        p.readlinkat(AT_FDCWD, URANDOM, 64).0 == neg(EINVAL),
    );

    for (flags, answer) in OPENS {
        let fd = p.openat(AT_FDCWD, URANDOM, flags | O_CLOEXEC, 0o600);
        p.check(
            &format!("an open with flags {flags:#o} answers {answer}"),
            if answer == 0 {
                fd >= 0
            } else {
                fd == neg(answer) as i32
            },
        );
        if fd >= 0 {
            p.close(fd);
        }
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "entropy/urandom",
    run,
    covers: &[
        Syscall::N_newfstatat,
        Syscall::N_openat,
        Syscall::N_fstat,
        Syscall::N_lseek,
        Syscall::N_fchmod,
        Syscall::N_close,
        Syscall::N_faccessat,
        Syscall::N_fchmodat,
        Syscall::N_truncate,
        Syscall::N_unlinkat,
        Syscall::N_mkdirat,
        Syscall::N_readlinkat,
    ],
    symbols: &[
        "fstatat",
        "openat",
        "fstat",
        "lseek",
        "fchmod",
        "close",
        "faccessat",
        "fchmodat",
        "truncate",
        "unlinkat",
        "mkdirat",
        "readlinkat",
    ],
    ..DEFAULTS
};
