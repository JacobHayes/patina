//! cred/caps — capability sets through `capget`/`capset`
//! (kernel/capability.c):
//!
//! * version negotiation: an unknown version is `EINVAL` and the kernel
//!   writes its own (`_LINUX_CAPABILITY_VERSION_3`) back into the header;
//!   with a NULL data pointer the same probe answers 0 (the version query);
//!   the current version with NULL data answers 0;
//! * an unprivileged caller's effective, permitted and inheritable sets are
//!   empty, for pid 0 and its own pid; a pid no process has is `ESRCH`, a
//!   negative one `EINVAL`;
//! * `capset` of the empty sets succeeds (for pid 0 and the own pid); an
//!   effective set beyond the permitted one, or a permitted set beyond the
//!   current one, is `EPERM`; any other pid is `EPERM`; an unknown version
//!   is `EINVAL`.
//!
//! The deprecated 32-bit versions are never used: the kernel logs a
//! warning for them.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{CAPABILITY_V3, CapData, Probe, Who, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `CAP_NET_RAW`'s bit.
const NET_RAW: u32 = 1 << 13;

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;
    let (r, version, _) = p.capget(CAPABILITY_V3, Who::Caller, false);
    p.check(
        "the current version with NULL data answers 0",
        r == 0 && version == CAPABILITY_V3,
    );
    let (r, version, _) = p.capget(0, Who::Caller, false);
    p.check(
        "an unknown version with NULL data answers 0, the kernel's version written back",
        r == 0 && version == CAPABILITY_V3,
    );
    let (r, version, _) = p.capget(0, Who::Caller, true);
    p.check(
        "an unknown version with data is EINVAL, the kernel's version written back",
        r == neg(EINVAL) && version == CAPABILITY_V3,
    );
    let empty = [CapData::default(); 2];
    let (r, _, sets) = p.capget(CAPABILITY_V3, Who::Caller, true);
    p.check(
        "an unprivileged caller's sets are empty",
        r == 0 && sets == empty,
    );
    let (r, _, sets) = p.capget(CAPABILITY_V3, Who::Own(pid), true);
    p.check("its own pid answers the same", r == 0 && sets == empty);
    p.check(
        "a pid no process has is ESRCH",
        p.capget(CAPABILITY_V3, Who::Missing, true).0 == neg(ESRCH),
    );
    p.check(
        "a negative pid is EINVAL",
        p.capget(CAPABILITY_V3, Who::Raw(-1), true).0 == neg(EINVAL),
    );

    p.check(
        "capset of the empty sets succeeds",
        p.capset(CAPABILITY_V3, Who::Caller, CapData::default()) == 0,
    );
    p.check(
        "for the own pid too",
        p.capset(CAPABILITY_V3, Who::Own(pid), CapData::default()) == 0,
    );
    p.check(
        "an effective set beyond the permitted one is EPERM",
        p.capset(
            CAPABILITY_V3,
            Who::Caller,
            CapData {
                effective: NET_RAW,
                ..CapData::default()
            },
        ) == neg(EPERM),
    );
    p.check(
        "a permitted set beyond the current one is EPERM",
        p.capset(
            CAPABILITY_V3,
            Who::Caller,
            CapData {
                permitted: NET_RAW,
                ..CapData::default()
            },
        ) == neg(EPERM),
    );
    p.check(
        "another pid is EPERM",
        p.capset(CAPABILITY_V3, Who::Missing, CapData::default()) == neg(EPERM),
    );
    p.check(
        "an unknown version is EINVAL",
        p.capset(0, Who::Caller, CapData::default()) == neg(EINVAL),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "cred/caps",
    run,
    covers: &[Syscall::N_capget, Syscall::N_capset],
    symbols: &["syscall", "getpid"],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
