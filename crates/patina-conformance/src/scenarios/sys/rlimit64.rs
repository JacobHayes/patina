//! sys/rlimit64 — glibc's large-file spellings of the limit calls,
//! `getrlimit64` and `setrlimit64` (glibc resource/; on a 64-bit target the
//! plain calls with `rlim64_t` limits, over `prlimit64(0, …)`), which Rust's
//! std imports for the descriptor limit. sys/rlimit through these symbols:
//!
//! * the descriptor limit's soft value is 1024 (the virtual kernel's, and
//!   what the harness pins the native run to), at most its hard value (the
//!   host's, recorded by relation); `prlimit64` reads the same; the soft
//!   value moves below the hard one and back;
//! * a soft value above the hard one is `EINVAL`, and so is an unknown
//!   resource; `getrlimit64` into a NULL limit succeeds (glibc issues
//!   `prlimit64(0, resource, NULL, NULL)`, which asks for nothing), and so
//!   does `setrlimit64` from one (NULL as prlimit64's new limit sets
//!   nothing; verified on glibc 2.39);
//! * the core limit lowers to zero and its hard value is not raised again,
//!   to a finite value or to infinity (`EPERM`); `prlimit64` reads it back.
//!
//! libc only: glibc's two symbols, imported (the shim defines them).

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{GetRlimit64, INFINITY, Probe, SetRlimit64, Shown, Who, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

use super::rlimit::{FD_LIMIT, UNKNOWN_RESOURCE};

pub fn run(p: &Probe) {
    let (get, set): (GetRlimit64, SetRlimit64) = (getrlimit64, setrlimit64);
    let nofile = RLIMIT_NOFILE as i32;
    let core = RLIMIT_CORE as i32;

    let (r, soft, hard) = p.getrlimit64(get, nofile, Shown::Soft);
    p.check(
        "the descriptor limit's soft value is 1024, within the hard one",
        r == 0 && soft == FD_LIMIT && soft <= hard,
    );
    let (r, s, h) = p.prlimit64(Who::Caller, nofile, None, true, Shown::Soft);
    p.check("prlimit64 reads the same", r == 0 && (s, h) == (soft, hard));
    p.check(
        "the soft value moves below the hard one",
        p.setrlimit64_kept(set, nofile, 512, hard) == 0,
    );
    let (r, s, _) = p.getrlimit64(get, nofile, Shown::Soft);
    p.check("and reads back", r == 0 && s == 512);
    p.check(
        "and back up",
        p.setrlimit64_kept(set, nofile, FD_LIMIT, hard) == 0,
    );
    p.check(
        "a soft value above the hard one is EINVAL",
        p.setrlimit64(set, core, Some((1, 0))) == neg(EINVAL),
    );
    p.check(
        "an unknown resource is EINVAL to getrlimit64",
        p.getrlimit64(get, UNKNOWN_RESOURCE, Shown::Both).0 == neg(EINVAL),
    );
    p.check(
        "and to setrlimit64",
        p.setrlimit64(set, UNKNOWN_RESOURCE, Some((0, 0))) == neg(EINVAL),
    );
    p.check(
        "a NULL limit is no fault to getrlimit64: glibc asks prlimit64 for no old limit",
        p.getrlimit64_null(get, nofile) == 0,
    );
    p.check(
        "and none to setrlimit64: glibc hands prlimit64 NULL as the new limit, which sets nothing",
        p.setrlimit64(set, nofile, None) == 0,
    );
    let (r, s, _) = p.getrlimit64(get, nofile, Shown::Soft);
    p.check("the limit is unchanged", r == 0 && s == FD_LIMIT);
    p.check(
        "the core limit lowers to zero",
        p.setrlimit64(set, core, Some((0, 0))) == 0,
    );
    let (r, s, h) = p.getrlimit64(get, core, Shown::Both);
    p.check("and reads back", r == 0 && (s, h) == (0, 0));
    p.check(
        "raising the hard limit again is EPERM",
        p.setrlimit64(set, core, Some((0, 1))) == neg(EPERM),
    );
    p.check(
        "to infinity too",
        p.setrlimit64(set, core, Some((INFINITY, INFINITY))) == neg(EPERM),
    );
    let (r, s, h) = p.prlimit64(Who::Caller, core, None, true, Shown::Both);
    p.check(
        "prlimit64 reads what setrlimit64 set",
        r == 0 && (s, h) == (0, 0),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/rlimit64",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_getrlimit,
        Syscall::N_setrlimit,
        Syscall::N_prlimit64,
    ],
    symbols: &["getrlimit64", "setrlimit64", "syscall"],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
