//! sys/hostname — naming the host (kernel/sys.c): `sethostname` and
//! `setdomainname` need `CAP_SYS_ADMIN` in the UTS namespace's user
//! namespace and check it before the name's length, so an unprivileged
//! caller is `EPERM` even for a name longer than the kernel's 64 bytes (what
//! root would be told `EINVAL`, leaving the names alone). `gethostname(3)`
//! and `uname`'s node name are sys/uname's.

use crate::catalog::{DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::EPERM;
use patina_dst_syscalls::Syscall;

/// One byte past `__NEW_UTS_LEN`.
const TOO_LONG: i64 = 65;
const NAME: &str = "patina-conformance-name-longer-than-the-kernel-allows-for-a-uts-name";

pub fn run(p: &Probe) {
    p.check(
        "sethostname is EPERM before the length is looked at",
        p.set_uts_name(Syscall::N_sethostname, NAME, TOO_LONG) == neg(EPERM),
    );
    p.check(
        "setdomainname too",
        p.set_uts_name(Syscall::N_setdomainname, NAME, TOO_LONG) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/hostname",
    run,
    covers: &[Syscall::N_sethostname, Syscall::N_setdomainname],
    symbols: &["syscall"],
    needs: &[Need::Unprivileged],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "sethostname is Trap(privileged) with no closing arc in the registry (patina-syscalls linux.rs; docs/arcs/syscall-conformance.md §7): a named fatal trap where the unprivileged kernel answers EPERM (its libc spelling is syscall(2): the shim defines no sethostname wrapper)",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall sethostname (nr",
        },
    }],
    ..DEFAULTS
};
