//! fs/fifo — glibc's `mkfifo(3)` and `mkfifoat(3)` (glibc
//! sysdeps/unix/sysv/linux/mkfifoat.c: `mknodat(dirfd, path, S_IFIFO|mode,
//! 0)`): a FIFO whose permissions are the mode under the umask, relative to
//! the working directory or a directory descriptor (`0666` under a `027`
//! umask is `0640`); opened non-blocking it
//! reads with no writer (fs/paths refuses a writer with no reader). An
//! existing name is EEXIST, a missing parent ENOENT, a path through a file
//! ENOTDIR, a closed directory descriptor EBADF, a file descriptor as the
//! directory ENOTDIR.
//!
//! libc only: the libc vehicle of the mknodat row spells `mknodat`.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

/// `mkfifo(path, mode)`, or `mkfifoat(dirfd, path, mode)` given a `dirfd`.
fn make(p: &Probe, dirfd: Option<i32>, path: &str, mode: u32) -> i64 {
    let c = CString::new(path).expect("no interior NUL");
    // SAFETY: a NUL-terminated path.
    let result = fold_errno(i64::from(unsafe {
        match dirfd {
            None => mkfifo(c.as_ptr(), mode),
            Some(dirfd) => mkfifoat(dirfd, c.as_ptr(), mode),
        }
    }));
    let builder = match dirfd {
        None => p.rec.event("mkfifo", result),
        Some(AT_FDCWD) => p.rec.event("mkfifoat", result).arg("dirfd", "AT_FDCWD"),
        Some(dirfd) => p
            .rec
            .event("mkfifoat", result)
            .arg("dirfd", dirfd)
            .norm("args.dirfd", crate::observe::Norm::Relative("fd")),
    };
    builder.arg("path", path).arg("mode", mode).emit();
    result
}

/// The entry at `path` is a FIFO with these permission bits.
fn is_fifo(p: &Probe, path: &str, perm: u32) -> bool {
    let (r, st) = p.newfstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW);
    r == 0 && st.is_some_and(|st| st.kind == "fifo" && st.perm == perm)
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    let dir = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dir >= 0);

    let fifo = format!("{root}/p");
    p.check("umask 027, from the suite's 022", p.umask(0o027) == 0o022);
    p.check("mkfifo p 0666", make(p, None, &fifo, 0o666) == 0);
    p.check(
        "p is a FIFO, its mode under the umask",
        is_fifo(p, &fifo, 0o640),
    );
    p.check("umask back to 022", p.umask(0o022) == 0o027);
    p.check(
        "mkfifo of an existing name is EEXIST",
        make(p, None, &fifo, 0o600) == neg(EEXIST),
    );
    p.check(
        "mkfifo under a missing directory is ENOENT",
        make(p, None, &format!("{root}/missing/p"), 0o600) == neg(ENOENT),
    );
    p.check(
        "mkfifo through a file is ENOTDIR",
        make(p, None, &format!("{file}/p"), 0o600) == neg(ENOTDIR),
    );
    p.check(
        "mkfifoat relative to a directory descriptor",
        make(p, Some(dir), "q", 0o600) == 0,
    );
    p.check("q is a FIFO", is_fifo(p, &format!("{root}/q"), 0o600));
    p.check(
        "mkfifoat AT_FDCWD",
        make(p, Some(AT_FDCWD), &format!("{root}/r"), 0o640) == 0,
    );
    p.check("r is a FIFO", is_fifo(p, &format!("{root}/r"), 0o640));
    p.check(
        "mkfifoat relative to a closed number is EBADF",
        make(p, Some(4000), "s", 0o600) == neg(EBADF),
    );
    p.check(
        "mkfifoat relative to a file is ENOTDIR",
        make(p, Some(fd), "s", 0o600) == neg(ENOTDIR),
    );

    let reader = p.openat(AT_FDCWD, &fifo, O_RDONLY | O_NONBLOCK, 0);
    p.check("a non-blocking reader opens with no writer", reader >= 0);
    p.check("and reads nothing", reader >= 0 && p.read(reader, 8).0 == 0);
    p.close(reader);
    p.close(fd);
    p.close(dir);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/fifo",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_mknodat,
        Syscall::N_openat,
        Syscall::N_newfstatat,
        Syscall::N_read,
        Syscall::N_close,
        Syscall::N_umask,
    ],
    symbols: &[
        "mkfifo", "mkfifoat", "openat", "fstatat", "read", "close", "umask",
    ],
    ..DEFAULTS
};
