//! sys/rlimit — resource limits other than `RLIMIT_MEMLOCK` (the memory
//! family owns it) through `getrlimit`, `setrlimit` and `prlimit64`
//! (kernel/sys.c do_prlimit):
//!
//! * the descriptor limit's soft value is 1024 — the virtual kernel's, and
//!   what the harness pins the native run to — at most its hard value (the
//!   host's); `prlimit64` with no new limit reads the same, for pid 0 and
//!   for the caller's own pid;
//! * the soft value moves freely below the hard one and back up to it;
//! * a soft value above the hard one is `EINVAL`; an unknown resource is
//!   `EINVAL` to every row; `prlimit64` of a pid no process has is `ESRCH`;
//! * a hard limit may be lowered, never raised again without
//!   `CAP_SYS_RESOURCE` (`EPERM`, `RLIM_INFINITY` included); `prlimit64`
//!   answers the old limits while it sets the new.
//!
//! The host's hard limits are recorded by relation (`soft <= hard`) or as
//! `kept` where a call hands one back unchanged; `RLIMIT_CORE` is lowered to
//! zero (this process dumps no core then) so every later value is one the
//! scenario set.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{INFINITY, Probe, Shown, Who, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// The virtual kernel's descriptor limit, which the harness pins natively.
const FD_LIMIT: u64 = 1024;
/// One past the last resource (`RLIM_NLIMITS`).
const UNKNOWN_RESOURCE: i32 = 16;

pub fn run(p: &Probe) {
    let (r, soft, hard) = p.getrlimit(RLIMIT_NOFILE as i32, Shown::Soft);
    p.check(
        "the descriptor limit's soft value is 1024, within the hard one",
        r == 0 && soft == FD_LIMIT && soft <= hard,
    );
    let (r, s, h) = p.prlimit64(Who::Caller, RLIMIT_NOFILE as i32, None, true, Shown::Soft);
    p.check(
        "prlimit64 of pid 0 reads the same",
        r == 0 && (s, h) == (soft, hard),
    );
    let pid = p.getpid() as i32;
    let (r, s, h) = p.prlimit64(Who::Own(pid), RLIMIT_NOFILE as i32, None, true, Shown::Soft);
    p.check(
        "prlimit64 of the caller's pid reads the same",
        r == 0 && (s, h) == (soft, hard),
    );
    let (r, _, _) = p.getrlimit(RLIMIT_STACK as i32, Shown::Relation);
    p.check("the stack limit reads", r == 0);

    p.check(
        "the soft value moves below the hard one",
        p.setrlimit_kept(RLIMIT_NOFILE as i32, 512, hard) == 0,
    );
    let (r, s, _) = p.getrlimit(RLIMIT_NOFILE as i32, Shown::Soft);
    p.check("and reads back", r == 0 && s == 512);
    p.check(
        "and back up",
        p.setrlimit_kept(RLIMIT_NOFILE as i32, FD_LIMIT, hard) == 0,
    );

    p.check(
        "a soft value above the hard one is EINVAL",
        p.setrlimit(RLIMIT_CORE as i32, 1, 0) == neg(EINVAL),
    );
    p.check(
        "an unknown resource is EINVAL to getrlimit",
        p.getrlimit(UNKNOWN_RESOURCE, Shown::Both).0 == neg(EINVAL),
    );
    p.check(
        "to setrlimit",
        p.setrlimit(UNKNOWN_RESOURCE, 0, 0) == neg(EINVAL),
    );
    p.check(
        "and to prlimit64",
        p.prlimit64(Who::Caller, UNKNOWN_RESOURCE, None, true, Shown::Both)
            .0
            == neg(EINVAL),
    );
    p.check(
        "prlimit64 of a pid no process has is ESRCH",
        p.prlimit64(
            Who::Missing,
            RLIMIT_NOFILE as i32,
            None,
            true,
            Shown::Relation,
        )
        .0 == neg(ESRCH),
    );

    p.check(
        "the core limit lowers to zero",
        p.setrlimit(RLIMIT_CORE as i32, 0, 0) == 0,
    );
    let (r, s, h) = p.getrlimit(RLIMIT_CORE as i32, Shown::Both);
    p.check("and reads back", r == 0 && (s, h) == (0, 0));
    p.check(
        "raising the hard limit again is EPERM",
        p.setrlimit(RLIMIT_CORE as i32, 0, 1) == neg(EPERM),
    );
    p.check(
        "to infinity too",
        p.setrlimit(RLIMIT_CORE as i32, INFINITY, INFINITY) == neg(EPERM),
    );
    let (r, s, h) = p.prlimit64(
        Who::Caller,
        RLIMIT_CORE as i32,
        Some((0, 0)),
        true,
        Shown::Both,
    );
    p.check(
        "prlimit64 answers the old limits while it sets the new",
        r == 0 && (s, h) == (0, 0),
    );
    p.check(
        "prlimit64 refuses a soft value above the hard one",
        p.prlimit64(
            Who::Caller,
            RLIMIT_CORE as i32,
            Some((1, 0)),
            false,
            Shown::Both,
        )
        .0 == neg(EINVAL),
    );
    p.check(
        "and a raised hard one",
        p.prlimit64(
            Who::Caller,
            RLIMIT_CORE as i32,
            Some((0, 1)),
            false,
            Shown::Both,
        )
        .0 == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/rlimit",
    run,
    covers: &[
        Syscall::N_getrlimit,
        Syscall::N_setrlimit,
        Syscall::N_prlimit64,
    ],
    symbols: &["getrlimit", "setrlimit", "getpid", "syscall"],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
