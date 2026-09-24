//! mem/userfaultfd — userfaultfd descriptors (fs/userfaultfd.c), on a host
//! that keeps kernel-fault handling to privileged callers
//! (`Need::RestrictedUserfaultfd`: `vm.unprivileged_userfaultfd` 0, its
//! default and the configuration the virtual kernel declares):
//!
//! * without `UFFD_USER_MODE_ONLY` the caller needs `CAP_SYS_PTRACE`
//!   (`userfaultfd_syscall_allowed`), checked before the flags, so even an
//!   unknown flag is `EPERM`;
//! * with it, an unknown flag is `EINVAL` (`new_userfaultfd`), and otherwise
//!   the caller gets a read-only descriptor honoring `O_CLOEXEC` and
//!   `O_NONBLOCK`;
//! * a new descriptor answers a read `EINVAL` until the `UFFDIO_API`
//!   handshake, which (asking for no feature) succeeds and reports the
//!   features and ioctls: which features is partly the build's (the
//!   write-protect and minor-fault ones), so only those every configuration
//!   has are asserted; after it a nonblocking read with no fault pending is
//!   `EAGAIN`.
//!
//! Neither creating a descriptor nor the handshake registers anything: the
//! probe never asks it to handle a fault.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::Norm;
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const UFFD_USER_MODE_ONLY: i64 = 1;
/// No userfaultfd flag.
const UNKNOWN_FLAG: i64 = 0x10;
/// `struct uffdio_api`.
#[repr(C)]
struct Api {
    api: u64,
    features: u64,
    ioctls: u64,
}
const UFFD_API: u64 = 0xaa;
/// `_IOWR(0xAA, 0x3F, struct uffdio_api)`.
const UFFDIO_API: u64 = 0xc018_aa3f;
/// `sizeof(struct uffd_msg)`.
const MESSAGE: usize = 32;
/// The features no configuration masks (fs/userfaultfd.c `userfaultfd_api`
/// drops only the write-protect and minor-fault ones): the events (fork,
/// remap, remove, unmap), missing faults on hugetlbfs and shmem, SIGBUS,
/// the thread id, the exact address, poison and move.
const COMMON_FEATURES: u64 = 0x1fe | (1 << 11) | (1 << 14) | (1 << 16);
/// `UFFD_API_IOCTLS`: `_UFFDIO_REGISTER`, `_UFFDIO_UNREGISTER`, `_UFFDIO_API`.
const API_IOCTLS: u64 = (1 << 63) | 0b11;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let userfaultfd = |flags: i64| p.call_observed(Syscall::N_userfaultfd, [flags, 0, 0, 0, 0, 0]);
    p.check(
        "handling kernel faults is EPERM (no CAP_SYS_PTRACE)",
        userfaultfd(O_CLOEXEC as i64) == neg(EPERM),
    );
    p.check(
        "before the flags are checked",
        userfaultfd(UNKNOWN_FLAG) == neg(EPERM),
    );
    p.check(
        "user-mode-only with an unknown flag is EINVAL",
        userfaultfd(UFFD_USER_MODE_ONLY | UNKNOWN_FLAG) == neg(EINVAL),
    );
    for (flags, fd_flags, fl_flags, label) in [
        (
            O_CLOEXEC,
            FD_CLOEXEC,
            0,
            "a user-mode-only descriptor, read-only and close-on-exec",
        ),
        (O_NONBLOCK, 0, O_NONBLOCK, "a nonblocking one"),
    ] {
        let fd = p.call_unrecorded(
            Syscall::N_userfaultfd,
            [UFFD_USER_MODE_ONLY | flags as i64, 0, 0, 0, 0, 0],
        );
        p.rec
            .event(Syscall::N_userfaultfd.name(), fd)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        p.require(label, fd >= 0);
        let fd = fd as i32;
        p.check(
            label,
            p.fcntl(fd, F_GETFD, 0) == fd_flags as i64
                && p.fcntl(fd, F_GETFL, 0) == (O_RDONLY | fl_flags) as i64,
        );
        if flags == O_NONBLOCK {
            handshake(p, fd);
        }
        p.close(fd);
    }
}

/// The `UFFDIO_API` handshake every user runs first: it registers nothing.
fn handshake(p: &Probe, fd: i32) {
    p.check(
        "reading before the handshake is EINVAL",
        p.read(fd, MESSAGE).0 == neg(EINVAL),
    );
    let mut api = Api {
        api: UFFD_API,
        features: 0,
        ioctls: 0,
    };
    p.check(
        "UFFDIO_API with no feature asked for succeeds",
        p.call_observed(
            Syscall::N_ioctl,
            [
                fd as i64,
                UFFDIO_API as i64,
                &mut api as *mut Api as i64,
                0,
                0,
                0,
            ],
        ) == 0,
    );
    p.check(
        "it offers the features every configuration has",
        api.features & COMMON_FEATURES == COMMON_FEATURES,
    );
    p.check(
        "and the register, unregister and API ioctls",
        api.ioctls == API_IOCTLS,
    );
    p.check(
        "then a read with no fault pending is EAGAIN",
        p.read(fd, MESSAGE).0 == neg(EAGAIN),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/userfaultfd",
    run,
    // glibc has no wrapper for the row: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_userfaultfd,
        Syscall::N_ioctl,
        Syscall::N_read,
        Syscall::N_fcntl,
        Syscall::N_close,
    ],
    needs: &[Need::Unprivileged, Need::RestrictedUserfaultfd],
    gaps: &[Gap {
        status: Status::Pending(Arc::Privileged),
        vehicles: Vehicle::KERNEL,
        what: "userfaultfd is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)) where the kernel answers EPERM for kernel-fault handling (no CAP_SYS_PTRACE) and hands any caller a user-mode-only descriptor",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(SIGABRT),
            diagnostic: TRAP,
        },
    }],
    ..DEFAULTS
};

#[cfg(target_arch = "x86_64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall userfaultfd (nr 323, class privileged";
#[cfg(target_arch = "aarch64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall userfaultfd (nr 282, class privileged";
