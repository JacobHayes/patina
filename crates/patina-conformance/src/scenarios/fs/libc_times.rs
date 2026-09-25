//! fs/libc_times — glibc's `lutimes(3)` and `futimes(3)` (glibc
//! sysdeps/unix/sysv/linux/lutimes.c, futimes.c: `utimensat` of a symlink
//! itself and of a descriptor):
//!
//! * `lutimes` sets a symlink's own access and modification times to the
//!   microsecond and leaves its target's alone; NULL sets both to now;
//! * `futimes` sets a descriptor's file's times, NULL to now, and needs no
//!   write access as the owner;
//! * a missing name is ENOENT, a closed descriptor EBADF, a microsecond
//!   count past 999999 EINVAL.
//!
//! Absolute clock readings are the host's business, so "now" is checked by
//! relation: atime and mtime one instant, later than an earlier now-based
//! stamp (the entry's creation) with a pause between, never against the
//! explicit past (fs/times: where the virtual clock's epoch lies is the
//! runtime's business).
//!
//! libc only: neither has a row of its own name.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, StatView, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const NANOS: i128 = 1_000_000_000;

/// `(atime, mtime)` in nanoseconds, read without recording.
fn times_of(p: &Probe, path: &str) -> Option<(i128, i128)> {
    let (r, st): (i64, Option<StatView>) = p
        .rec
        .quiet(|| p.newfstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW));
    (r == 0).then_some(())?;
    st.map(|st| (st.atime_ns, st.mtime_ns))
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let link = format!("{root}/l");
    let fd = p.openat(AT_FDCWD, &file, O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    let created = times_of(p, &file);
    let link_created = times_of(p, &link);
    p.require("stat f and l", created.is_some() && link_created.is_some());
    let (created, link_created) = (created.unwrap(), link_created.unwrap());

    // ---- futimes -------------------------------------------------------------
    p.check(
        "futimes sets explicit times",
        p.futimes(fd, Some([(1_000, 250_000), (2_000, 500_000)])) == 0,
    );
    p.check(
        "to the microsecond",
        times_of(p, &file) == Some((1_000 * NANOS + 250_000_000, 2_000 * NANOS + 500_000_000)),
    );
    p.tick();
    p.check("futimes NULL sets now", p.futimes(fd, None) == 0);
    p.check(
        "both to one instant after the file's creation",
        times_of(p, &file).is_some_and(|(a, m)| a == m && m > created.1),
    );
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("open f read-only", reader >= 0);
    p.check(
        "the owner needs no write access",
        p.futimes(reader, Some([(3_000, 0), (4_000, 0)])) == 0
            && times_of(p, &file) == Some((3_000 * NANOS, 4_000 * NANOS)),
    );
    p.check(
        "futimes of a closed number is EBADF",
        p.futimes(4000, Some([(1, 0), (1, 0)])) == neg(EBADF),
    );
    p.check(
        "a microsecond count past 999999 is EINVAL",
        p.futimes(fd, Some([(1, 1_000_000), (1, 0)])) == neg(EINVAL),
    );

    // ---- lutimes -------------------------------------------------------------
    p.check(
        "lutimes sets the symlink's own times",
        p.lutimes(&link, Some([(5_000, 1), (6_000, 999_999)])) == 0,
    );
    p.check(
        "to the microsecond",
        times_of(p, &link) == Some((5_000 * NANOS + 1_000, 6_000 * NANOS + 999_999_000)),
    );
    p.check(
        "and leaves its target's alone",
        times_of(p, &file) == Some((3_000 * NANOS, 4_000 * NANOS)),
    );
    p.tick();
    p.check("lutimes NULL sets now", p.lutimes(&link, None) == 0);
    p.check(
        "the link's both to one instant after its creation",
        times_of(p, &link).is_some_and(|(a, m)| a == m && m > link_created.1),
    );
    p.check(
        "lutimes of a file sets the file's",
        p.lutimes(&file, Some([(7_000, 0), (8_000, 0)])) == 0
            && times_of(p, &file) == Some((7_000 * NANOS, 8_000 * NANOS)),
    );
    p.check(
        "lutimes of a missing name is ENOENT",
        p.lutimes(&format!("{root}/missing"), None) == neg(ENOENT),
    );
    p.check(
        "lutimes through a file is ENOTDIR",
        p.lutimes(&format!("{file}/x"), None) == neg(ENOTDIR),
    );
    p.check(
        "a microsecond count past 999999 is EINVAL",
        p.lutimes(&link, Some([(1, 0), (1, 1_000_000)])) == neg(EINVAL),
    );
    p.close(fd);
    p.close(reader);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/libc_times",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_utimensat,
        Syscall::N_openat,
        Syscall::N_symlinkat,
        Syscall::N_newfstatat,
        Syscall::N_close,
        Syscall::N_nanosleep,
    ],
    symbols: &[
        "lutimes",
        "futimes",
        "openat",
        "symlinkat",
        "fstatat",
        "close",
        "nanosleep",
    ],
    ..DEFAULTS
};
