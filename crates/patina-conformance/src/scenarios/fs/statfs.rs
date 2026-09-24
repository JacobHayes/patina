//! fs/statfs — statfs / fstatfs (and x86_64's ustat): what a filesystem
//! reports about itself. The type, sizes, counts and fsid are the host
//! filesystem's business, so they are checked by relation: statfs by path,
//! through a symlink, and fstatfs by a file, directory or O_PATH descriptor
//! (fdget_raw) of one filesystem agree; free ≤ total, available ≤ free; a
//! nonzero type and block count, a power-of-two block size of at least 512,
//! and a fragment size equal to it (every filesystem the run directory can be
//! on). The kernel's own answers compare exactly: f_namelen is NAME_MAX,
//! f_flags carries ST_VALID (fs/statfs.c calculate_f_flags) and not
//! ST_RDONLY; a pipe's descriptor reports PIPEFS_MAGIC and an eventfd's
//! ANON_INODE_FS_MAGIC; ENOENT, ENOTDIR, ENAMETOOLONG, EBADF for a closed
//! descriptor (a NULL buffer is fs/statfs_fault). ustat(2) finds the run directory's
//! device (its superblock's s_dev), is EINVAL for a device with no mounted
//! filesystem — judged before the buffer — and EFAULT for a NULL buffer.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, ST_VALID, Statfs, neg};
use libc::*;

/// linux/magic.h.
const PIPEFS_MAGIC: i64 = 0x5049_5045;
const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;

/// A device number no filesystem is mounted on (major 0xfff, minor 0xff in
/// the kernel's 32-bit encoding).
#[cfg(target_arch = "x86_64")]
const NO_DEVICE: u64 = 0x000f_ffff;

/// The members of one filesystem's `statfs` that stay put between two calls
/// (free counts move with any writer on the host, and so does XFS's inode
/// total, which it derives from free space).
fn identity(st: &Statfs) -> (i64, i64, [i32; 2], i64, i64, i64, u64) {
    (
        st.f_type,
        st.f_bsize,
        st.f_fsid,
        st.f_namelen,
        st.f_frsize,
        st.f_flags,
        st.f_blocks,
    )
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let link = format!("{root}/l");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);

    // ---- statfs by path ----------------------------------------------------
    let (r, by_path) = p.statfs(&root, false);
    p.require("statfs the run directory", r == 0 && by_path.is_some());
    let by_path = by_path.unwrap();
    // NAME_MAX is every filesystem the run directory can be on here (ext4,
    // XFS, tmpfs, btrfs, overlayfs: 255); vfat or NFS with short names would
    // differ.
    p.check(
        "f_namelen is NAME_MAX",
        by_path.f_namelen == i64::from(NAME_MAX),
    );
    p.check(
        "f_flags carries ST_VALID and not ST_RDONLY",
        by_path.f_flags & ST_VALID != 0 && by_path.f_flags & ST_RDONLY as i64 == 0,
    );
    p.check(
        "free blocks never exceed the total, available never exceed free",
        by_path.f_bfree <= by_path.f_blocks && by_path.f_bavail <= by_path.f_bfree,
    );
    p.check(
        "free inodes never exceed the total",
        by_path.f_ffree <= by_path.f_files,
    );
    p.check(
        "a real filesystem has a type and blocks",
        by_path.f_type != 0 && by_path.f_blocks > 0,
    );
    p.check(
        "the block size is a power of two of at least 512",
        by_path.f_bsize >= 512 && (by_path.f_bsize as u64).is_power_of_two(),
    );
    p.check(
        "the fragment size is the block size",
        by_path.f_frsize == by_path.f_bsize,
    );
    let (r, via_file) = p.statfs(&file, false);
    p.check(
        "statfs of a file names the same filesystem",
        r == 0 && via_file.is_some_and(|st| identity(&st) == identity(&by_path)),
    );
    let (r, via_link) = p.statfs(&link, false);
    p.check(
        "statfs follows a symlink",
        r == 0 && via_link.is_some_and(|st| identity(&st) == identity(&by_path)),
    );
    p.check(
        "statfs of a missing name is ENOENT",
        p.statfs(&format!("{root}/missing"), false).0 == neg(ENOENT),
    );
    p.check(
        "statfs through a file is ENOTDIR",
        p.statfs(&format!("{file}/x"), false).0 == neg(ENOTDIR),
    );
    p.check(
        "statfs of an empty path is ENOENT",
        p.statfs("", false).0 == neg(ENOENT),
    );
    p.check(
        "statfs of a 256-byte component is ENAMETOOLONG",
        p.statfs(&format!("{root}/{}", "n".repeat(256)), false).0 == neg(ENAMETOOLONG),
    );

    // ---- fstatfs by descriptor ---------------------------------------------
    let (r, by_fd) = p.fstatfs(fd, false);
    p.check(
        "fstatfs of a file agrees with statfs",
        r == 0 && by_fd.is_some_and(|st| identity(&st) == identity(&by_path)),
    );
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dirfd >= 0);
    let (r, by_dir) = p.fstatfs(dirfd, false);
    p.check(
        "fstatfs of a directory agrees with statfs",
        r == 0 && by_dir.is_some_and(|st| identity(&st) == identity(&by_path)),
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open f O_PATH", location >= 0);
    let (r, by_location) = p.fstatfs(location, false);
    p.check(
        "fstatfs accepts an O_PATH descriptor",
        r == 0 && by_location.is_some_and(|st| identity(&st) == identity(&by_path)),
    );
    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);
    let (r, pipefs) = p.fstatfs(pipe[0], false);
    p.check(
        "a pipe lives on pipefs",
        r == 0 && pipefs.is_some_and(|st| st.f_type == PIPEFS_MAGIC),
    );
    let event = p.eventfd2(0, EFD_CLOEXEC);
    p.require("eventfd2", event >= 0);
    let (r, anon) = p.fstatfs(event, false);
    p.check(
        "an eventfd lives on the anonymous-inode filesystem",
        r == 0 && anon.is_some_and(|st| st.f_type == ANON_INODE_FS_MAGIC),
    );
    p.check(
        "fstatfs of a closed descriptor is EBADF",
        p.fstatfs(4000, false).0 == neg(EBADF),
    );

    // ---- ustat (x86_64) ----------------------------------------------------
    #[cfg(target_arch = "x86_64")]
    {
        // The device number is the host's (or the virtual kernel's): read
        // unobserved through the vehicle, used only as ustat's argument.
        let dev = p.rec.quiet(|| p.fstat(dirfd).1.map(|st| st.dev));
        p.require("fstat the run directory", dev.is_some());
        let dev = dev.unwrap_or_default();
        p.check(
            "ustat finds the run directory's device",
            p.ustat(dev, "run-directory", false) == 0,
        );
        p.check(
            "ustat into a NULL buffer is EFAULT",
            p.ustat(dev, "run-directory", true) == neg(EFAULT),
        );
        p.check(
            "ustat of a device with no filesystem is EINVAL, before the buffer",
            p.ustat(NO_DEVICE, "none", true) == neg(EINVAL),
        );
    }

    for f in [fd, dirfd, location, pipe[0], pipe[1], event] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/statfs",
    run,
    covers: &[
        Syscall::N_statfs,
        Syscall::N_fstatfs,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_ustat,
        Syscall::N_openat,
        Syscall::N_symlinkat,
        Syscall::N_pipe2,
        Syscall::N_eventfd2,
        Syscall::N_fstat,
        Syscall::N_close,
    ],
    symbols: &[
        "statfs",
        "fstatfs",
        "syscall",
        "openat",
        "symlinkat",
        "pipe2",
        "eventfd",
        "fstat",
        "close",
    ],
    ..DEFAULTS
};
