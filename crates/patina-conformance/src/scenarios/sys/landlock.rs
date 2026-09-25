//! sys/landlock — Landlock rulesets (security/landlock/syscalls.c), which an
//! unprivileged caller may build freely; only enforcing one needs
//! `no_new_privs` or `CAP_SYS_ADMIN`:
//!
//! * `landlock_create_ruleset` with `LANDLOCK_CREATE_RULESET_VERSION`, a
//!   NULL attribute and size 0 answers the ABI version, 4 (Linux 6.7's
//!   network rules; 6.10 moves it to 5); any other flag, or the version
//!   flag with an attribute size, is `EINVAL`;
//! * a ruleset's attribute (`copy_min_struct_from_user`): unreadable
//!   `EFAULT` before its size is looked at, then a size short of
//!   `handled_access_fs` `EINVAL`, past a page `E2BIG`; an access right the
//!   kernel does not know is `EINVAL`, handling none `ENOMSG`; otherwise a
//!   close-on-exec read-write ruleset descriptor;
//! * `landlock_add_rule` refuses a flag (`EINVAL`), then wants a ruleset
//!   descriptor (none: `EBADF`; another kind: `EBADFD`), then a known rule
//!   type (`EINVAL`), then for a path rule (`add_rule_path_beneath`) a
//!   readable attribute (`EFAULT`) allowing something (`ENOMSG`) the
//!   ruleset handles (`EINVAL`), and only then an open parent (`EBADF`); a
//!   network port rule on a ruleset handling no network access is `EINVAL`;
//! * `landlock_restrict_self` without `no_new_privs` is `EPERM`
//!   (`CAP_SYS_ADMIN`) before its flags and descriptor are looked at.
//!
//! The probe never restricts itself: `landlock_restrict_self` is only ever
//! passed descriptor -1 with a flag no kernel defines, which is `EINVAL`
//! past the privilege check on every kernel.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const LANDLOCK_CREATE_RULESET_VERSION: i64 = 1;
/// No `LANDLOCK_CREATE_RULESET_*` or `LANDLOCK_RESTRICT_SELF_*` flag on any
/// kernel.
const UNKNOWN_FLAG: i64 = 1 << 31;
const LANDLOCK_RULE_PATH_BENEATH: i64 = 1;
const LANDLOCK_RULE_NET_PORT: i64 = 2;
/// No `LANDLOCK_RULE_*` type.
const UNKNOWN_RULE: i64 = 99;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
/// Far past every filesystem access right.
const UNKNOWN_ACCESS: u64 = 1 << 40;
const ACCESS_NET_BIND_TCP: u64 = 1;

/// `struct landlock_ruleset_attr` as Linux 6.8 has it.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}
const ATTR_SIZE: i64 = 16;

/// `struct landlock_path_beneath_attr` (packed).
#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// `struct landlock_net_port_attr`.
#[repr(C)]
struct NetPort {
    allowed_access: u64,
    port: u64,
}

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let create = |attr: *const RulesetAttr, size: i64, flags: i64| {
        p.call_observed(
            Syscall::N_landlock_create_ruleset,
            [attr as i64, size, flags, 0, 0, 0],
        )
    };
    p.check(
        "the version query answers the ABI version 4",
        create(std::ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION) == 4,
    );
    let handled = |fs: u64| RulesetAttr {
        handled_access_fs: fs,
        handled_access_net: 0,
    };
    let read_file = handled(ACCESS_FS_READ_FILE);
    p.check(
        "the version flag with an attribute is EINVAL",
        create(&read_file, ATTR_SIZE, LANDLOCK_CREATE_RULESET_VERSION) == neg(EINVAL),
    );
    p.check(
        "an unknown flag is EINVAL",
        create(std::ptr::null(), 0, UNKNOWN_FLAG) == neg(EINVAL),
    );
    p.check(
        "an unreadable attribute is EFAULT, before its size is looked at",
        create(std::ptr::null(), 4, 0) == neg(EFAULT),
    );
    p.check(
        "a size short of handled_access_fs is EINVAL",
        create(&read_file, 4, 0) == neg(EINVAL),
    );
    p.check(
        "a size past a page is E2BIG",
        create(&read_file, 4097, 0) == neg(E2BIG),
    );
    p.check(
        "an access right the kernel does not know is EINVAL",
        create(&handled(UNKNOWN_ACCESS), ATTR_SIZE, 0) == neg(EINVAL),
    );
    p.check(
        "a ruleset handling nothing is ENOMSG",
        create(&handled(0), ATTR_SIZE, 0) == neg(ENOMSG),
    );
    let ruleset = p.call_unrecorded(
        Syscall::N_landlock_create_ruleset,
        [
            &read_file as *const RulesetAttr as i64,
            ATTR_SIZE,
            0,
            0,
            0,
            0,
        ],
    );
    p.rec
        .event(Syscall::N_landlock_create_ruleset.name(), ruleset)
        .arg("handled_access_fs", "READ_FILE")
        .norm("ret", Norm::Relative("fd"))
        .emit();
    p.require("a ruleset handling READ_FILE", ruleset >= 0);
    let ruleset = ruleset as i32;
    p.check(
        "a ruleset descriptor is read-write",
        p.fcntl(ruleset, F_GETFL, 0) == O_RDWR as i64,
    );
    p.check(
        "and close-on-exec",
        p.fcntl(ruleset, F_GETFD, 0) == FD_CLOEXEC as i64,
    );

    let dir = p.openat(AT_FDCWD, &p.dir(), O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dir >= 0);
    let beneath = |allowed_access: u64, parent_fd: i32| PathBeneath {
        allowed_access,
        parent_fd,
    };
    let add = |fd: i32, rule: i64, attr: *const u8, flags: i64| {
        p.call_observed(
            Syscall::N_landlock_add_rule,
            [fd as i64, rule, attr as i64, flags, 0, 0],
        )
    };
    let reads = beneath(ACCESS_FS_READ_FILE, dir);
    let reads = &reads as *const PathBeneath as *const u8;
    p.check(
        "landlock_add_rule with a flag is EINVAL",
        add(ruleset, LANDLOCK_RULE_PATH_BENEATH, reads, 1) == neg(EINVAL),
    );
    p.check(
        "a descriptor not open is EBADF, before the rule type",
        add(-1, UNKNOWN_RULE, reads, 0) == neg(EBADF),
    );
    p.check(
        "a descriptor that is no ruleset is EBADFD",
        add(dir, LANDLOCK_RULE_PATH_BENEATH, reads, 0) == neg(EBADFD),
    );
    p.check(
        "an unknown rule type is EINVAL",
        add(ruleset, UNKNOWN_RULE, reads, 0) == neg(EINVAL),
    );
    p.check(
        "an unreadable attribute is EFAULT",
        add(ruleset, LANDLOCK_RULE_PATH_BENEATH, std::ptr::null(), 0) == neg(EFAULT),
    );
    // Each attribute below names no open parent, so an answer other than
    // EBADF shows the check that comes before the parent is looked up.
    for (allowed, errno, label) in [
        (0, ENOMSG, "allowing nothing is ENOMSG, before the parent"),
        (
            ACCESS_FS_WRITE_FILE,
            EINVAL,
            "an access right the ruleset does not handle is EINVAL, before the parent",
        ),
        (
            ACCESS_FS_READ_FILE,
            EBADF,
            "then a parent descriptor not open is EBADF",
        ),
    ] {
        let attr = beneath(allowed, -1);
        p.check(
            label,
            add(
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const PathBeneath as *const u8,
                0,
            ) == neg(errno),
        );
    }
    let port = NetPort {
        allowed_access: ACCESS_NET_BIND_TCP,
        port: 80,
    };
    p.check(
        "a port rule on a ruleset handling no network access is EINVAL",
        add(
            ruleset,
            LANDLOCK_RULE_NET_PORT,
            &port as *const NetPort as *const u8,
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "a rule reading files beneath the run directory",
        add(ruleset, LANDLOCK_RULE_PATH_BENEATH, reads, 0) == 0,
    );
    p.check(
        "landlock_restrict_self without no_new_privs is EPERM before its flags and descriptor",
        p.call_observed(
            Syscall::N_landlock_restrict_self,
            [-1, UNKNOWN_FLAG, 0, 0, 0, 0],
        ) == neg(EPERM),
    );
    p.close(dir);
    p.close(ruleset);
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/landlock",
    run,
    // glibc has no wrapper for these rows: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_landlock_create_ruleset,
        Syscall::N_landlock_add_rule,
        Syscall::N_landlock_restrict_self,
        Syscall::N_fcntl,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    needs: &[Need::Unprivileged, Need::Landlock],
    kernel_floor: Some(KernelFloor {
        release: "6.7",
        why: "Landlock ABI 4: network port rules (security/landlock/syscalls.c)",
    }),
    gaps: &[Gap {
        status: Status::Pending(Arc::Privileged),
        vehicles: Vehicle::KERNEL,
        what: "landlock_create_ruleset is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)), as are landlock_add_rule and landlock_restrict_self, where the kernel builds rulesets for anyone and refuses enforcing one without no_new_privs as EPERM (no CAP_SYS_ADMIN)",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall landlock_create_ruleset (nr 444, class privileged",
        },
    }],
    ..DEFAULTS
};
