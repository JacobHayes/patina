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
//!   `EAGAIN`, and a second handshake is `EINVAL`;
//! * poll answers `POLLERR` until the handshake, and after it, for a
//!   nonblocking descriptor with no fault pending, no event;
//! * as a file it is read-only (a write `EBADF`), seeks nowhere
//!   (`noop_llseek`: 0) and has an inode of its own, the caller's (`fchmod`
//!   succeeds); a read into a buffer outside the user address space is
//!   `EFAULT` before the descriptor's own read (`vfs_read`'s `access_ok`);
//!   `do_vfs_ioctl` answers its generic requests first (no `fasync`, no
//!   size, a page-sized block, freezing `EPERM`), the descriptor's own
//!   ioctl the rest (`EINVAL`).
//!
//! Neither creating a descriptor nor the handshake registers anything: the
//! probe never asks it to handle a fault.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::observe::Norm;
use crate::probe::{IoctlArg, Probe, neg};
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
/// Generic requests (`fs.h`, `ioctls.h`).
const FIOASYNC: u64 = 0x5452;
const FIOQSIZE: u64 = 0x5460;
const FIGETBSZ: u64 = 0x2;
const FIFREEZE: u64 = 0xc004_5877;
const FS_IOC_GETFLAGS: u64 = 0x8008_6601;
/// An address past every architecture's user address space.
const KERNEL_ADDRESS: i64 = 0xffff_8000_0000_0000_u64 as i64;
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
            descriptor(p, fd);
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
    p.check(
        "polling before the handshake is POLLERR",
        p.ppoll(&[(fd, POLLIN)], Some(0)) == (1, vec![POLLERR]),
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
    p.check(
        "and a poll finds no event",
        p.ppoll(&[(fd, POLLIN)], Some(0)) == (0, vec![0]),
    );
    let mut again = Api {
        api: UFFD_API,
        features: 0,
        ioctls: 0,
    };
    p.check(
        "a second handshake is EINVAL",
        p.call_observed(
            Syscall::N_ioctl,
            [
                fd as i64,
                UFFDIO_API as i64,
                &mut again as *mut Api as i64,
                0,
                0,
                0,
            ],
        ) == neg(EINVAL),
    );
}

/// What the descriptor answers as a file: it is read-only, so a write is
/// `EBADF` (`vfs_write`, even of nothing); its `llseek` is `noop_llseek`, so a
/// seek leaves the position at 0 for any whence the kernel knows, and a
/// whence past `SEEK_MAX` is `EINVAL`; and its inode is its own and the
/// caller's (`anon_inode_create_getfile`), so `fchmod` succeeds.
fn descriptor(p: &Probe, fd: i32) {
    p.check("a write is EBADF", p.write(fd, &[0; 8]) == neg(EBADF));
    p.check("even of nothing", p.write(fd, &[]) == neg(EBADF));
    for whence in [SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE] {
        p.check(
            &format!("a seek with whence {whence} stays at 0"),
            p.lseek(fd, 5, whence) == 0,
        );
    }
    p.check(
        "a whence past SEEK_MAX is EINVAL",
        p.lseek(fd, 0, SEEK_HOLE + 1) == neg(EINVAL),
    );
    p.check("fchmod of it succeeds", p.fchmod(fd, 0o600) == 0);
    // `do_vfs_ioctl` answers its requests before the descriptor's own ioctl,
    // which refuses the rest (`EINVAL`).
    for (name, request, arg, errno, value) in [
        ("FIOASYNC", FIOASYNC, IoctlArg::In(0), 0, None),
        ("FIOASYNC", FIOASYNC, IoctlArg::In(1), ENOTTY, None),
        ("FIOQSIZE", FIOQSIZE, IoctlArg::Out, ENOTTY, None),
        ("FIGETBSZ", FIGETBSZ, IoctlArg::Out, 0, Some(4096)),
        ("FIFREEZE", FIFREEZE, IoctlArg::Out, EPERM, None),
        (
            "FS_IOC_GETFLAGS",
            FS_IOC_GETFLAGS,
            IoctlArg::Out,
            EINVAL,
            None,
        ),
    ] {
        let (r, got) = p.ioctl(fd, request, name, arg);
        p.check(
            &format!("{name} of it"),
            if errno == 0 {
                r == 0 && got == value
            } else {
                r == neg(errno)
            },
        );
    }
    p.check(
        "a read into a buffer past the user address space is EFAULT, before the file's own read",
        p.call_observed(
            Syscall::N_read,
            [fd as i64, KERNEL_ADDRESS, MESSAGE as i64, 0, 0, 0],
        ) == neg(EFAULT),
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
        Syscall::N_ppoll,
        Syscall::N_write,
        Syscall::N_lseek,
        Syscall::N_fchmod,
    ],
    needs: &[Need::Unprivileged, Need::RestrictedUserfaultfd],
    ..DEFAULTS
};
