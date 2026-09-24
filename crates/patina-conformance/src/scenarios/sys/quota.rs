//! sys/quota — disk quotas (fs/quota/quota.c). The capability a quota
//! command needs (`CAP_SYS_ADMIN` for all but the queries of the caller's
//! own ids, `check_quotactl_permission`) is checked only after the
//! filesystem is found and found to support quotas, so the answers every
//! caller gets first are:
//!
//! * `quotactl`: a type past `MAXQUOTAS` is `EINVAL`; with no device,
//!   `Q_SYNC` syncs every filesystem's quotas and answers 0 (no privilege)
//!   and any other command is `ENODEV`; the device is looked up next, so a
//!   missing path is `ENOENT` and a path that is no block device `ENOTBLK`;
//! * `quotactl_fd`: a descriptor not open is `EBADF`, then a type past
//!   `MAXQUOTAS` is `EINVAL`.
//!
//! Whether a command on a real filesystem reaches the capability check is
//! the filesystem's business (quota operations or `ENOSYS`), so it is not
//! asserted. `Q_QUOTAOFF` is named only with a path that is no device, which
//! root is refused too. The libc vehicle goes through glibc's `quotactl`,
//! which the shim does not define (registry `Absent`): it reaches it through
//! `dlsym`. `quotactl_fd` has no wrapper; glibc's spelling is `syscall(2)`.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

const Q_SYNC: i64 = 0x80_0001;
const Q_QUOTAOFF: i64 = 0x80_0003;
const Q_GETFMT: i64 = 0x80_0004;
const USRQUOTA: i64 = 0;
/// `MAXQUOTAS`, the first type no filesystem has.
const NO_TYPE: i64 = 3;

/// `QCMD(command, type)`.
const fn qcmd(command: i64, kind: i64) -> i64 {
    (command << 8) | kind
}

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let root = p.dir();
    let missing = CString::new(format!("{root}/missing")).unwrap();
    let file = CString::new(format!("{root}/file")).unwrap();
    let fd = p.openat(AT_FDCWD, &format!("{root}/file"), O_CREAT | O_WRONLY, 0o600);
    p.require("create a regular file", fd >= 0);
    p.close(fd);
    let quotactl =
        |cmd: i64, special: i64| p.call_observed(Syscall::N_quotactl, [cmd, special, 0, 0, 0, 0]);
    p.check(
        "a type past MAXQUOTAS is EINVAL",
        quotactl(qcmd(Q_GETFMT, NO_TYPE), 0) == neg(EINVAL),
    );
    p.check(
        "with no device, Q_GETFMT is ENODEV",
        quotactl(qcmd(Q_GETFMT, USRQUOTA), 0) == neg(ENODEV),
    );
    p.check(
        "with no device, Q_SYNC syncs every filesystem, needing no privilege",
        quotactl(qcmd(Q_SYNC, USRQUOTA), 0) == 0,
    );
    p.check(
        "a missing device is ENOENT before any permission check",
        quotactl(qcmd(Q_QUOTAOFF, USRQUOTA), missing.as_ptr() as i64) == neg(ENOENT),
    );
    p.check(
        "a device that is no block device is ENOTBLK",
        quotactl(qcmd(Q_QUOTAOFF, USRQUOTA), file.as_ptr() as i64) == neg(ENOTBLK),
    );

    let quotactl_fd =
        |fd: i64, cmd: i64| p.call_observed(Syscall::N_quotactl_fd, [fd, cmd, 0, 0, 0, 0]);
    p.check(
        "quotactl_fd of a descriptor not open is EBADF",
        quotactl_fd(-1, qcmd(Q_GETFMT, USRQUOTA)) == neg(EBADF),
    );
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dirfd >= 0);
    p.check(
        "then a type past MAXQUOTAS is EINVAL",
        quotactl_fd(dirfd as i64, qcmd(Q_GETFMT, NO_TYPE)) == neg(EINVAL),
    );
    p.close(dirfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/quota",
    run,
    covers: &[
        Syscall::N_quotactl,
        Syscall::N_quotactl_fd,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &["quotactl", "syscall", "openat", "close"],
    resolves: &["quotactl"],
    needs: &[Need::Unprivileged],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: Vehicle::KERNEL,
            what: "quotactl is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)), as is quotactl_fd, where every caller is first answered from the command, the device and the descriptor",
            failure: Failure::Stops {
                events: 2,
                ending: Ending::Signal(SIGABRT),
                diagnostic: TRAP,
            },
        },
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: &[Vehicle::Libc],
            what: "the shim does not define glibc's quotactl (registry `Absent`): a guest importing it is refused by the pre-run audit, and `dlsym` does not find it (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the libc leg stops at its first call",
            failure: Failure::Stops {
                events: 2,
                ending: Ending::Exit(101),
                diagnostic: "sys/quota: cannot continue: glibc's quotactl resolves",
            },
        },
    ],
    ..DEFAULTS
};

#[cfg(target_arch = "x86_64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall quotactl (nr 179, class privileged";
#[cfg(target_arch = "aarch64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall quotactl (nr 60, class privileged";
