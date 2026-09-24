//! What `statfs(2)`/`fstatfs(2)`/`ustat(2)` report: the filesystem a path or a
//! descriptor is on, described the way the kernel describes it.
//!
//! Every entry a path can name is on ONE deterministic volume, an ext4-like
//! filesystem on block device 8:1 whose description is a constant (so it is
//! the same on record and replay and on every host): 4 KiB blocks, fixed
//! block and inode counts, `NAME_MAX` names, and `f_flags` as
//! `calculate_f_flags` builds them — `ST_VALID` always, plus the mount's
//! `relatime`, the atime policy the filesystem stamps by. A descriptor with no
//! entry on the volume is on one of the kernel's pseudo-filesystems, which
//! answer through `simple_statfs`: an anonymous pipe on pipefs, a socket or a
//! socketpair end on sockfs, an eventfd, signalfd or epoll instance on
//! anon_inodefs. The entropy device `/dev/urandom` is on a mount of its own,
//! devtmpfs (a tmpfs), described by constants like the volume. Every `f_fsid`
//! is derived from the filesystem's device. Linux only: the C `statfs` family
//! is the Linux one.

use std::ffi::{c_char, c_int};

use crate::fdtable::FdKind;
use crate::{
    EBADF, EFAULT, EINVAL, ENOENT, PATINA_FS_PIPEFS, PATINA_FS_SOCKFS, PATINA_FS_VOLUME, fail,
    fs_device, path_from_c, paths, resolve_fd, set_errno, thread,
};

/// The kernel's (and glibc's) 64-bit `struct statfs`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelStatfs {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [i32; 2],
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
    pub f_spare: [i64; 4],
}

/// linux/magic.h.
const EXT4_SUPER_MAGIC: i64 = 0xEF53;
const PIPEFS_MAGIC: i64 = 0x5049_5045;
const SOCKFS_MAGIC: i64 = 0x534F_434B;
const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const MQUEUE_MAGIC: i64 = 0x1980_0202;

/// `statfs(2)` `f_flags`: the answer is valid (`ST_VALID`, set by
/// `calculate_f_flags` on every answer) and the mount's atime policy.
const ST_VALID: i64 = 0x0020;
const ST_NOSUID: i64 = 0x0002;
const ST_RELATIME: i64 = 0x1000;

/// `NAME_MAX`.
const NAME_MAX: i64 = 255;

/// The anonymous devices anon_inodefs and devtmpfs are on.
const ANON_INODEFS_DEVICE: (u32, u32) = (0, 15);
const DEVTMPFS_DEVICE: (u32, u32) = (0, 5);
/// The IPC namespace's internal mqueue mount, where `mq_open` descriptors live.
const MQUEUE_DEVICE: (u32, u32) = (0, 26);

/// A filesystem a node can be on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Filesystem {
    Volume,
    Pipefs,
    Sockfs,
    AnonInodefs,
    Devtmpfs,
    Mqueue,
}

impl Filesystem {
    const ALL: [Filesystem; 6] = [
        Filesystem::Volume,
        Filesystem::Pipefs,
        Filesystem::Sockfs,
        Filesystem::AnonInodefs,
        Filesystem::Devtmpfs,
        Filesystem::Mqueue,
    ];

    fn device(self) -> (u32, u32) {
        match self {
            Filesystem::Volume => fs_device(PATINA_FS_VOLUME),
            Filesystem::Pipefs => fs_device(PATINA_FS_PIPEFS),
            Filesystem::Sockfs => fs_device(PATINA_FS_SOCKFS),
            Filesystem::AnonInodefs => ANON_INODEFS_DEVICE,
            Filesystem::Devtmpfs => DEVTMPFS_DEVICE,
            Filesystem::Mqueue => MQUEUE_DEVICE,
        }
    }

    /// `f_fsid`: the device, encoded as `simple_statfs` encodes it
    /// (`huge_encode_dev`, the `new_encode_dev` word, split into two). The
    /// pseudo-filesystems answer exactly that; ext4 and tmpfs derive theirs
    /// from the superblock UUID, which the model takes to be the device.
    fn fsid(self) -> [i32; 2] {
        let (major, minor) = self.device();
        let id = u64::from((minor & 0xff) | (major << 8) | ((minor & !0xff) << 12));
        [id as u32 as i32, (id >> 32) as u32 as i32]
    }

    fn describe(self) -> KernelStatfs {
        match self {
            Filesystem::Volume => KernelStatfs {
                f_type: EXT4_SUPER_MAGIC,
                f_bsize: 4096,
                f_blocks: 1 << 20,
                f_bfree: 1 << 19,
                f_bavail: 1 << 19,
                f_files: 1 << 20,
                f_ffree: 1 << 19,
                f_fsid: self.fsid(),
                f_namelen: NAME_MAX,
                f_frsize: 4096,
                f_flags: ST_VALID | ST_RELATIME,
                f_spare: [0; 4],
            },
            Filesystem::Devtmpfs => KernelStatfs {
                f_type: TMPFS_MAGIC,
                f_bsize: crate::PAGE_SIZE as i64,
                f_blocks: 1 << 18,
                f_bfree: 1 << 18,
                f_bavail: 1 << 18,
                f_files: 1 << 18,
                // The one node on it: the entropy device.
                f_ffree: (1 << 18) - 1,
                f_fsid: self.fsid(),
                f_namelen: NAME_MAX,
                f_frsize: crate::PAGE_SIZE as i64,
                f_flags: ST_VALID | ST_NOSUID | ST_RELATIME,
                f_spare: [0; 4],
            },
            Filesystem::Pipefs
            | Filesystem::Sockfs
            | Filesystem::AnonInodefs
            | Filesystem::Mqueue => KernelStatfs {
                f_type: match self {
                    Filesystem::Pipefs => PIPEFS_MAGIC,
                    Filesystem::Sockfs => SOCKFS_MAGIC,
                    Filesystem::Mqueue => MQUEUE_MAGIC,
                    _ => ANON_INODE_FS_MAGIC,
                },
                f_bsize: crate::PAGE_SIZE as i64,
                f_fsid: self.fsid(),
                f_namelen: NAME_MAX,
                f_flags: ST_VALID,
                ..KernelStatfs::default()
            },
        }
    }
}

/// The filesystem a descriptor is on (`fdget_raw`: an `O_PATH` descriptor
/// names its entry on the volume). The captured standard streams have no
/// modeled node, and answer `EBADF` as `fstat` does.
fn descriptor_filesystem(raw_fd: c_int) -> Result<Filesystem, c_int> {
    let resolved = resolve_fd(raw_fd)?;
    match resolved.kind {
        FdKind::File | FdKind::Dir | FdKind::OPath => Ok(Filesystem::Volume),
        FdKind::Pipe => match thread::pipe_filesystem(raw_fd) {
            Some(PATINA_FS_PIPEFS) => Ok(Filesystem::Pipefs),
            Some(PATINA_FS_SOCKFS) => Ok(Filesystem::Sockfs),
            Some(_) => Ok(Filesystem::Volume),
            None => Err(EBADF),
        },
        FdKind::Socket => Ok(Filesystem::Sockfs),
        FdKind::EventFd | FdKind::SignalFd | FdKind::Epoll => Ok(Filesystem::AnonInodefs),
        FdKind::MessageQueue => Ok(Filesystem::Mqueue),
        FdKind::Urandom => Ok(Filesystem::Devtmpfs),
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => Err(EBADF),
    }
}

/// Copy a description out, as `do_statfs_native` does last: a NULL buffer is
/// `EFAULT`, after everything else has been judged.
fn copy_out(description: KernelStatfs, out: *mut KernelStatfs) -> c_int {
    if out.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: `out` is non-null and writable per the C ABI contract.
    unsafe { out.write(description) };
    set_errno(0);
    0
}

/// `statfs(2)`: the filesystem `path` (a trailing symlink followed) is on.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string; `out`, when
/// non-null, to a writable `struct statfs`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_statfs(path: *const c_char, out: *mut KernelStatfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let path = match path_from_c(path) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    match paths::resolve(paths::AT_FDCWD, &path, 0) {
        Ok(resolved) if resolved.metadata.is_some() => copy_out(Filesystem::Volume.describe(), out),
        Ok(resolved) if paths::is_urandom(&resolved.path) => {
            copy_out(Filesystem::Devtmpfs.describe(), out)
        }
        Ok(_) => fail(ENOENT),
        Err(errno) => fail(errno),
    }
}

/// `fstatfs(2)`: the filesystem a descriptor is on.
///
/// # Safety
/// `out`, when non-null, must point to a writable `struct statfs`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_fstatfs(raw_fd: c_int, out: *mut KernelStatfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    match descriptor_filesystem(raw_fd) {
        Ok(filesystem) => copy_out(filesystem.describe(), out),
        Err(errno) => fail(errno),
    }
}

/// The kernel's `struct ustat` on x86_64.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelUstat {
    pub f_tfree: i32,
    pub f_tinode: u64,
    pub f_fname: [u8; 6],
    pub f_fpack: [u8; 6],
}

/// `ustat(2)`: the free-block and free-inode counts of the filesystem mounted
/// on device `dev` (the kernel's 32-bit `new_encode_dev` word). A device with
/// no filesystem is `EINVAL`, judged before the buffer (`vfs_ustat`).
///
/// # Safety
/// `out`, when non-null, must point to a writable `struct ustat`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_ustat(dev: u32, out: *mut KernelUstat) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let major = (dev & 0xfff00) >> 8;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    let Some(filesystem) = Filesystem::ALL
        .into_iter()
        .find(|filesystem| filesystem.device() == (major, minor))
    else {
        return fail(EINVAL);
    };
    if out.is_null() {
        return fail(EFAULT);
    }
    let description = filesystem.describe();
    // SAFETY: `out` is non-null and writable per the C ABI contract.
    unsafe {
        out.write(KernelUstat {
            f_tfree: description.f_bfree as i32,
            f_tinode: description.f_ffree,
            ..KernelUstat::default()
        })
    };
    set_errno(0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_description_is_valid_and_names_name_max() {
        for filesystem in Filesystem::ALL {
            let description = filesystem.describe();
            assert_ne!(description.f_flags & ST_VALID, 0, "{filesystem:?}");
            assert_eq!(description.f_namelen, NAME_MAX, "{filesystem:?}");
            assert_ne!(description.f_type, 0, "{filesystem:?}");
        }
    }

    #[test]
    fn the_volume_describes_a_consistent_filesystem() {
        let volume = Filesystem::Volume.describe();
        assert!(volume.f_bfree <= volume.f_blocks && volume.f_bavail <= volume.f_bfree);
        assert!(volume.f_ffree <= volume.f_files);
        assert!(volume.f_bsize >= 512 && (volume.f_bsize as u64).is_power_of_two());
        assert_eq!(volume.f_frsize, volume.f_bsize);
    }

    #[test]
    fn the_filesystems_are_on_distinct_devices() {
        for (index, filesystem) in Filesystem::ALL.iter().enumerate() {
            for other in &Filesystem::ALL[index + 1..] {
                assert_ne!(filesystem.device(), other.device());
                assert_ne!(filesystem.fsid(), other.fsid());
            }
        }
    }

    /// RED before: `statfs("/dev/urandom")` was `ENOENT`, though the path
    /// opens and is a mount crossing to `openat2(RESOLVE_NO_XDEV)`.
    #[test]
    fn the_entropy_device_is_on_devtmpfs() {
        let mut out = KernelStatfs::default();
        // SAFETY: a valid path and a writable buffer.
        let answer = unsafe { patina_statfs(c"/dev/urandom".as_ptr(), &mut out) };
        assert_eq!(answer, 0);
        assert_eq!(out, Filesystem::Devtmpfs.describe());
        assert_eq!(out.f_type, TMPFS_MAGIC);
    }
}
