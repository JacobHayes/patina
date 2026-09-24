//! sys/uname — the kernel's self-description (kernel/sys.c newuname):
//! `sysname` is `Linux` and `machine` the architecture (kernel facts); the
//! release, version and node name are the host's, recorded as relations:
//! the release parses as a kernel release, the version and node name are
//! nonempty, and `gethostname(3)` answers the node name.
//!
//! Declared modeled difference: the virtual kernel's release is its ABI
//! level (`patina_dst_syscalls::VIRTUAL_ABI`) and its node name a knob, not
//! the host's; neither is compared by value.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::Probe;
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
    ..DEFAULTS
};
