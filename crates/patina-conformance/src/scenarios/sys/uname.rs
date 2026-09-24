//! sys/uname — the kernel's self-description (kernel/sys.c newuname):
//! `sysname` is `Linux` and `machine` the architecture (kernel facts); the
//! release, version and node name are the host's, recorded as relations:
//! the release parses as a kernel release, the version and node name are
//! nonempty, and `gethostname(3)` answers the node name.
//!
//! Declared modeled difference: the virtual kernel's release is its ABI
//! level (`patina_dst_syscalls::VIRTUAL_ABI`) and its node name a knob, not
//! the host's; neither is compared by value.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::Probe;
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// The `machine` a kernel of this architecture reports.
const MACHINE: &str = if cfg!(target_arch = "x86_64") {
    "x86_64"
} else {
    "aarch64"
};

pub fn run(p: &Probe) {
    let (r, uts) = p.uname();
    p.check("uname answers", r == 0);
    p.check("the kernel is Linux", uts.sysname == "Linux");
    p.check("the machine is this architecture", uts.machine == MACHINE);
    p.check(
        "the release parses as a kernel release",
        patina_dst_syscalls::parse_release(&uts.release).is_some(),
    );
    let mut name = [0u8; 65];
    // SAFETY: `name` is 65 writable bytes.
    let got = unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) };
    let host = String::from_utf8_lossy(&name[..name.iter().position(|b| *b == 0).unwrap_or(0)])
        .into_owned();
    p.mark(
        "gethostname",
        &[
            ("ret", Value::from(got)),
            (
                "matches_nodename",
                Value::from(got == 0 && host == uts.nodename),
            ),
        ],
    );
    p.check(
        "gethostname answers the node name",
        got == 0 && host == uts.nodename,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/uname",
    run,
    covers: &[Syscall::N_uname],
    symbols: &["uname", "gethostname"],
    gaps: &[Gap {
        status: Status::Pending(Arc::TimeTimersSchedIdentity),
        vehicles: Vehicle::ALL,
        what: "uname is SoftDeny(ENOSYS) in the registry and the C uname interposer answers ENOSYS too (c/posix/sched_identity.c): no virtual kernel identity is modeled, so nothing is written, and the shim's gethostname (\"patina\") matches no node name",
        failure: Failure::Differs(&[
            Difference::field(0, "uname", "errno", Observed::Str("ENOSYS")),
            Difference::field(0, "uname", "fields.machine", Observed::Null),
            Difference::field(0, "uname", "fields.nodename_nonempty", Observed::Null),
            Difference::field(0, "uname", "fields.release_parses", Observed::Null),
            Difference::field(0, "uname", "fields.sysname", Observed::Null),
            Difference::field(0, "uname", "fields.version_nonempty", Observed::Null),
            Difference::field(0, "uname", "ret", Observed::Int(-1)),
            Difference::check(1, "uname answers"),
            Difference::check(2, "the kernel is Linux"),
            Difference::check(3, "the machine is this architecture"),
            Difference::check(4, "the release parses as a kernel release"),
            Difference::field(
                5,
                "gethostname",
                "fields.matches_nodename",
                Observed::Bool(false),
            ),
            Difference::check(6, "gethostname answers the node name"),
        ]),
    }],
    ..DEFAULTS
};
