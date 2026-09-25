//! fs/posix_fadvise — glibc's `posix_fadvise` and `posix_fadvise64` (glibc
//! sysdeps/unix/sysv/linux/posix_fadvise64.c over fadvise64(2);
//! mm/fadvise.c): advice is a hint, so on a regular file every defined
//! advice is accepted, over the whole file (`len` 0) or a range; an unknown
//! advice or a negative length is `EINVAL`, a pipe `ESPIPE`, a closed
//! descriptor `EBADF`. The call returns its error number and leaves errno
//! as it was, on success and on error; events record it in the kernel
//! convention.
//!
//! libc only: glibc's two symbols, imported (the shim defines them).

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

type Fadvise = unsafe extern "C" fn(c_int, off64_t, off64_t, c_int) -> c_int;

/// An advice no kernel defines (POSIX_FADV_NORMAL 0 through NOREUSE 5).
const UNKNOWN_ADVICE: i32 = 99;

/// An errno value no call here sets, planted before each one.
const ERRNO_SENTINEL: i32 = EXDEV;

/// Every advice through `symbol`, then its refusals.
fn advise(p: &Probe, symbol: &str, f: Fadvise, file: i32, pipe: i32) {
    let call = |fd: i32, offset: i64, len: i64, advice: i32| {
        // SAFETY: the calling thread's errno; plain values.
        let (r, errno) = unsafe {
            *__errno_location() = ERRNO_SENTINEL;
            let r = -i64::from(f(fd, offset, len, advice));
            (r, *__errno_location())
        };
        p.rec
            .event(symbol, r)
            .arg("fd", fd)
            .norm("args.fd", crate::observe::Norm::Relative("fd"))
            .arg("offset", offset)
            .arg("len", len)
            .arg("advice", advice)
            .field("errno_kept", errno == ERRNO_SENTINEL)
            .emit();
        p.check(
            "errno is left as it was, success or error",
            errno == ERRNO_SENTINEL,
        );
        r
    };
    for advice in [
        POSIX_FADV_NORMAL,
        POSIX_FADV_SEQUENTIAL,
        POSIX_FADV_RANDOM,
        POSIX_FADV_NOREUSE,
        POSIX_FADV_WILLNEED,
        POSIX_FADV_DONTNEED,
    ] {
        p.check(
            "every defined advice is accepted over the whole file",
            call(file, 0, 0, advice) == 0,
        );
    }
    p.check(
        "and over a range",
        call(file, 4096, 8192, POSIX_FADV_WILLNEED) == 0,
    );
    p.check(
        "an unknown advice is EINVAL",
        call(file, 0, 0, UNKNOWN_ADVICE) == neg(EINVAL),
    );
    p.check(
        "a negative length is EINVAL",
        call(file, 0, -1, POSIX_FADV_NORMAL) == neg(EINVAL),
    );
    p.check(
        "a pipe is ESPIPE",
        call(pipe, 0, 0, POSIX_FADV_NORMAL) == neg(ESPIPE),
    );
    p.check(
        "a closed number is EBADF",
        call(4000, 0, 0, POSIX_FADV_NORMAL) == neg(EBADF),
    );
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let fd = p.openat(
        AT_FDCWD,
        &format!("{root}/f"),
        O_RDWR | O_CREAT | O_EXCL,
        0o644,
    );
    p.require("create f", fd >= 0);
    p.check("write a page", p.write(fd, &[7u8; 4096]) == 4096);
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);

    advise(p, "posix_fadvise", posix_fadvise, fd, rd);
    advise(p, "posix_fadvise64", posix_fadvise64, fd, rd);

    for fd in [fd, rd, wr] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/posix_fadvise",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_fadvise64,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "posix_fadvise",
        "posix_fadvise64",
        "openat",
        "write",
        "pipe2",
        "close",
    ],
    ..DEFAULTS
};
