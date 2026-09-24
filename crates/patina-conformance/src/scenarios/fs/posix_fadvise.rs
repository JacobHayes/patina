//! fs/posix_fadvise — glibc's `posix_fadvise` and `posix_fadvise64` (glibc
//! sysdeps/unix/sysv/linux/posix_fadvise64.c over fadvise64(2);
//! mm/fadvise.c): advice is a hint, so on a regular file every defined
//! advice is accepted, over the whole file (`len` 0) or a range; an unknown
//! advice or a negative length is `EINVAL`, a pipe `ESPIPE`, a closed
//! descriptor `EBADF`. The call returns its error number rather than setting
//! errno; events record it in the kernel convention.
//!
//! libc only, and through `dlsym`: the registry lists both `Absent` (the
//! shim does not define them), so the probe binary cannot import them (the
//! pre-run audit would refuse the whole binary). Under patina `dlsym` finds
//! neither: the shim's `__wrap_dlsym` routes only its entropy names.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

type Fadvise = unsafe extern "C" fn(c_int, off64_t, off64_t, c_int) -> c_int;

/// An advice no kernel defines (POSIX_FADV_NORMAL 0 through NOREUSE 5).
const UNKNOWN_ADVICE: i32 = 99;

/// Every advice through `symbol`, then its refusals.
fn advise(p: &Probe, symbol: &str, f: Fadvise, file: i32, pipe: i32) {
    let call = |fd: i32, offset: i64, len: i64, advice: i32| {
        // SAFETY: plain values.
        let r = -i64::from(unsafe { f(fd, offset, len, advice) });
        p.rec
            .event(symbol, r)
            .arg("fd", fd)
            .norm("args.fd", crate::observe::Norm::Relative("fd"))
            .arg("offset", offset)
            .arg("len", len)
            .arg("advice", advice)
            .emit();
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

    let plain = p.resolve("posix_fadvise");
    let wide = p.resolve("posix_fadvise64");
    p.require(
        "posix_fadvise and posix_fadvise64 resolve",
        plain.is_some() && wide.is_some(),
    );
    // SAFETY: glibc's definitions, by their documented types (on a 64-bit
    // target `off_t` is `off64_t`).
    let (plain, wide) = unsafe {
        (
            std::mem::transmute::<*mut c_void, Fadvise>(plain.unwrap()),
            std::mem::transmute::<*mut c_void, Fadvise>(wide.unwrap()),
        )
    };
    advise(p, "posix_fadvise", plain, fd, rd);
    advise(p, "posix_fadvise64", wide, fd, rd);

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
    resolves: &["posix_fadvise", "posix_fadvise64"],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the shim defines neither posix_fadvise nor posix_fadvise64 (registry `Absent`): a guest importing one is refused by the pre-run audit, and `dlsym` finds neither (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the gap lifts only once the shim both defines them and routes them there, or the scenario imports them directly",
            failure: Failure::Differs(&[
                Difference::field(4, "dlsym", "fields.resolved", Observed::Bool(false)),
                Difference::field(5, "dlsym", "fields.resolved", Observed::Bool(false)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "with neither resolved the scenario cannot continue",
            failure: Failure::Stops {
                events: 6,
                ending: Ending::Exit(101),
                diagnostic: "fs/posix_fadvise: cannot continue: posix_fadvise and posix_fadvise64 resolve",
            },
        },
    ],
    ..DEFAULTS
};
