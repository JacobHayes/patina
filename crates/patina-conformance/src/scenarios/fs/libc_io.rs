//! fs/libc_io — the plain-`off_t` spellings glibc also exports beside the
//! rows' own: `pread`/`pwrite` (the libc vehicle of the pread64/pwrite64 rows
//! spells `pread64`/`pwrite64`), `posix_fallocate` and `isatty`:
//!
//! * `pwrite` writes at an offset past the end (the hole reads as zeros) and
//!   `pread` reads at one without moving the descriptor's offset; through an
//!   `O_APPEND` descriptor `pwrite` appends whatever the offset (pwrite(2)
//!   BUGS); on a pipe both are ESPIPE, a negative offset EINVAL, the wrong
//!   access mode EBADF;
//! * `posix_fallocate` grows the file to the end of the range and returns
//!   its error number (EINVAL for a negative offset or a zero length, EBADF
//!   read-only, ESPIPE on a pipe);
//! * `isatty` is 1 for a terminal (a pseudoterminal master from
//!   `/dev/ptmx`), 0 for a file, a directory and a pipe (ENOTTY) and for a
//!   closed number (EBADF).
//!
//! libc only.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::{Vehicle, errno, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

fn pwrite_at(p: &Probe, fd: i32, data: &[u8], offset: i64) -> i64 {
    // SAFETY: a live buffer of its length.
    let r = fold_errno(unsafe { pwrite(fd, data.as_ptr().cast(), data.len(), offset) } as i64);
    p.rec
        .event("pwrite", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("len", data.len())
        .arg("offset", offset)
        .emit();
    r
}

fn pread_at(p: &Probe, fd: i32, len: usize, offset: i64) -> (i64, Vec<u8>) {
    let mut buf = vec![0u8; len];
    // SAFETY: a live buffer of `len` bytes.
    let r = fold_errno(unsafe { pread(fd, buf.as_mut_ptr().cast(), len, offset) } as i64);
    buf.truncate(r.max(0) as usize);
    let builder = p
        .rec
        .event("pread", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("len", len)
        .arg("offset", offset);
    let builder = if r >= 0 {
        builder.field("data", String::from_utf8_lossy(&buf).into_owned())
    } else {
        builder
    };
    builder.emit();
    (r, buf)
}

/// `posix_fallocate`, its returned error number in the kernel convention.
/// It returns the error rather than setting errno (POSIX), so an
/// implementation answering -1 records `ret` 1 (EPERM) and fails the checks:
/// that is the point, not a reason to fold errno here.
fn fallocate_range(p: &Probe, fd: i32, offset: i64, len: i64) -> i64 {
    // SAFETY: plain values.
    let r = -i64::from(unsafe { posix_fallocate(fd, offset, len) });
    p.rec
        .event("posix_fallocate", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("offset", offset)
        .arg("len", len)
        .emit();
    r
}

/// `isatty`: 1, or `-errno` for a 0 (errno cleared first, so a 0 that sets
/// none records 0 rather than an earlier call's errno).
fn tty(p: &Probe, fd: i32) -> i64 {
    // SAFETY: the calling thread's errno slot, then a plain descriptor number.
    let r = match unsafe {
        *__errno_location() = 0;
        isatty(fd)
    } {
        1 => 1,
        _ => -i64::from(errno()),
    };
    p.rec
        .event("isatty", r)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .emit();
    r
}

/// The file's size.
fn size_of_file(p: &Probe, fd: i32) -> i64 {
    let (r, st) = p.fstat(fd);
    if r == 0 {
        st.map_or(-1, |st| st.size)
    } else {
        r
    }
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("open f read-only", reader >= 0);
    let writer = p.openat(AT_FDCWD, &file, O_WRONLY | O_APPEND, 0);
    p.require("open f O_APPEND", writer >= 0);
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);

    // ---- pread / pwrite ------------------------------------------------------
    p.check("pwrite at 0", pwrite_at(p, fd, b"abcdef", 0) == 6);
    p.check("pwrite past the end", pwrite_at(p, fd, b"XY", 10) == 2);
    let (n, data) = pread_at(p, reader, 16, 0);
    p.check(
        "pread reads it back, the hole as zeros",
        n == 12 && data == b"abcdef\0\0\0\0XY",
    );
    let (n, data) = pread_at(p, reader, 3, 2);
    p.check("pread at an offset", n == 3 && data == b"cde");
    p.check(
        "neither moved the descriptor's offset",
        p.lseek(reader, 0, SEEK_CUR) == 0 && p.lseek(fd, 0, SEEK_CUR) == 0,
    );
    p.check(
        "pread at the end reads nothing",
        pread_at(p, reader, 4, 12).0 == 0,
    );
    p.check(
        "pwrite through O_APPEND appends whatever the offset",
        pwrite_at(p, writer, b"Z", 0) == 1 && pread_at(p, reader, 16, 12).1 == b"Z",
    );
    p.check(
        "pread at a negative offset is EINVAL",
        pread_at(p, reader, 4, -1).0 == neg(EINVAL),
    );
    p.check(
        "pwrite at a negative offset is EINVAL",
        pwrite_at(p, fd, b"x", -1) == neg(EINVAL),
    );
    p.check(
        "pread through a write-only descriptor is EBADF",
        pread_at(p, writer, 4, 0).0 == neg(EBADF),
    );
    p.check(
        "pwrite through a read-only descriptor is EBADF",
        pwrite_at(p, reader, b"x", 0) == neg(EBADF),
    );
    p.check(
        "pread on a pipe is ESPIPE",
        pread_at(p, rd, 4, 0).0 == neg(ESPIPE),
    );
    p.check(
        "pwrite on a pipe is ESPIPE",
        pwrite_at(p, wr, b"x", 0) == neg(ESPIPE),
    );

    // ---- posix_fallocate -----------------------------------------------------
    p.check(
        "posix_fallocate grows the file",
        fallocate_range(p, fd, 0, 8192) == 0,
    );
    p.check("to the end of the range", size_of_file(p, fd) == 8192);
    p.check(
        "posix_fallocate within the file keeps its size",
        fallocate_range(p, fd, 0, 4096) == 0 && size_of_file(p, fd) == 8192,
    );
    p.check(
        "posix_fallocate at a negative offset returns EINVAL",
        fallocate_range(p, fd, -1, 4096) == neg(EINVAL),
    );
    p.check(
        "posix_fallocate of a zero length returns EINVAL",
        fallocate_range(p, fd, 0, 0) == neg(EINVAL),
    );
    p.check(
        "posix_fallocate through a read-only descriptor returns EBADF",
        fallocate_range(p, reader, 0, 4096) == neg(EBADF),
    );
    p.check(
        "posix_fallocate on a pipe returns ESPIPE",
        fallocate_range(p, wr, 0, 4096) == neg(ESPIPE),
    );

    // ---- isatty ----------------------------------------------------------------
    let dir = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dir >= 0);
    p.check("a file is no terminal", tty(p, fd) == neg(ENOTTY));
    p.check("nor a directory", tty(p, dir) == neg(ENOTTY));
    p.check("nor a pipe", tty(p, rd) == neg(ENOTTY));
    p.check("a closed number is EBADF", tty(p, 4000) == neg(EBADF));
    let pty = p.openat(AT_FDCWD, "/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
    p.check("open a pseudoterminal master", pty >= 0);
    p.check("a terminal is one", tty(p, pty) == 1);

    for fd in [fd, reader, writer, rd, wr, dir, pty] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/libc_io",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_pread64,
        Syscall::N_pwrite64,
        Syscall::N_fallocate,
        Syscall::N_ioctl,
        Syscall::N_openat,
        Syscall::N_lseek,
        Syscall::N_fstat,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "pread",
        "pwrite",
        "posix_fallocate",
        "isatty",
        "openat",
        "lseek",
        "fstat",
        "pipe2",
        "close",
    ],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: &[Vehicle::Libc],
        what: "a run has no terminal: the only device the virtual volume serves is /dev/urandom (native shim paths.rs), so opening /dev/ptmx is ENOSYS, and the shim's isatty answers not-a-terminal for every descriptor (c/posix/fd_io.c isatty: host terminal state must not reach the guest)",
        failure: Failure::Differs(&[
            Difference::field(56, "openat", "ret", Observed::Int(-1)),
            Difference::field(56, "openat", "errno", Observed::Str("ENOSYS")),
            Difference::check(57, "open a pseudoterminal master"),
            Difference::field(58, "isatty", "args.fd", Observed::Int(-38)),
            Difference::field(58, "isatty", "ret", Observed::Int(-1)),
            Difference::field(58, "isatty", "errno", Observed::Str("EBADF")),
            Difference::check(59, "a terminal is one"),
            Difference::field(66, "close", "args.fd", Observed::Int(-38)),
            Difference::field(66, "close", "ret", Observed::Int(-1)),
            Difference::field(66, "close", "errno", Observed::Str("EBADF")),
        ]),
    }],
    ..DEFAULTS
};
