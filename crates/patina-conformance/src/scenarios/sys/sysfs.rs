//! sys/sysfs — the legacy filesystem-type table (fs/filesystems.c; x86_64
//! only, the generic table has no `sysfs` row): option 3 answers how many
//! types are registered (a host fact, recorded as positive); option 2 names
//! the type at an index and option 1 maps the name back to it; a name no
//! type has, an index past the last, and an unknown option are `EINVAL`.
//!
//! Which filesystems a kernel registers is the host's (or the virtual
//! kernel's) business: names are related, never recorded. The row is a
//! kernel-configuration fact (`CONFIG_SYSFS_SYSCALL`, `Need::SysfsSyscall`);
//! its registry row closes in the fs arc, which its gap names.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::EINVAL;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let count = p.sysfs_count(3);
    p.check("the number of filesystem types is positive", count > 0);
    let (r, name) = p.sysfs_name(0, "0");
    p.check("index 0 names a type", r == 0 && !name.is_empty());
    p.check(
        "its name maps back to index 0",
        p.sysfs_index(&name, "the name at index 0") == 0,
    );
    p.check(
        "a name no type has is EINVAL",
        p.sysfs_index("patina-no-such-fs", "patina-no-such-fs") == neg(EINVAL),
    );
    p.check(
        "the index past the last is EINVAL",
        p.sysfs_name(count.max(0), "count").0 == neg(EINVAL),
    );
    p.check("option 0 is EINVAL", p.sysfs_count(0) == neg(EINVAL));
    p.check("option 4 is EINVAL", p.sysfs_count(4) == neg(EINVAL));
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/sysfs",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_sysfs],
    needs: &[Need::SysfsSyscall],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: Vehicle::KERNEL,
        what: "sysfs is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door (its libc spelling is syscall(2): the shim defines no sysfs wrapper)",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall sysfs (nr",
        },
    }],
    ..DEFAULTS
};
