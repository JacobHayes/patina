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
//! answer through `simple_statfs`: an anonymous pipe on pipefs, a socket on
//! sockfs, an eventfd, signalfd or epoll instance on
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
const NSFS_MAGIC: i64 = 0x6e73_6673;

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
    Nsfs,
}

impl Filesystem {
    const ALL: [Filesystem; 7] = [
        Filesystem::Volume,
        Filesystem::Pipefs,
        Filesystem::Sockfs,
        Filesystem::AnonInodefs,
        Filesystem::Devtmpfs,
        Filesystem::Mqueue,
        Filesystem::Nsfs,
    ];

    /// The filesystem type as the kernel registers it (`register_filesystem`,
    /// the name `/proc/filesystems` and `sysfs(2)` list), or `None` for one
    /// that is only ever mounted internally (anon_inodefs).
    fn registered_name(self) -> Option<&'static str> {
        match self {
            Filesystem::Volume => Some("ext4"),
            Filesystem::Pipefs => Some("pipefs"),
            Filesystem::Sockfs => Some("sockfs"),
            Filesystem::AnonInodefs | Filesystem::Nsfs => None,
            Filesystem::Devtmpfs => Some("devtmpfs"),
            Filesystem::Mqueue => Some("mqueue"),
        }
    }

    fn device(self) -> (u32, u32) {
        match self {
            Filesystem::Volume => fs_device(PATINA_FS_VOLUME),
            Filesystem::Pipefs => fs_device(PATINA_FS_PIPEFS),
            Filesystem::Sockfs => fs_device(PATINA_FS_SOCKFS),
            Filesystem::AnonInodefs => ANON_INODEFS_DEVICE,
            Filesystem::Devtmpfs => DEVTMPFS_DEVICE,
            Filesystem::Mqueue => MQUEUE_DEVICE,
            Filesystem::Nsfs => fs_device(crate::PATINA_FS_NSFS),
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
            | Filesystem::Mqueue
            | Filesystem::Nsfs => KernelStatfs {
                f_type: match self {
                    Filesystem::Pipefs => PIPEFS_MAGIC,
                    Filesystem::Sockfs => SOCKFS_MAGIC,
                    Filesystem::Mqueue => MQUEUE_MAGIC,
                    Filesystem::Nsfs => NSFS_MAGIC,
                    _ => ANON_INODE_FS_MAGIC,
                },
                f_bsize: crate::PAGE_SIZE as i64,
                f_fsid: self.fsid(),
                f_namelen: NAME_MAX,
                // `simple_statfs` leaves it unset; `vfs_statfs` fills it in.
                f_frsize: crate::PAGE_SIZE as i64,
                f_flags: ST_VALID,
                ..KernelStatfs::default()
            },
        }
    }
}

/// A mount's two ids: `mnt_id`, the small one `STATX_MNT_ID` reports, and
/// `mnt_id_unique`, the 64-bit one `STATX_MNT_ID_UNIQUE` reports and
/// `statmount`/`listmount` take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MountIds {
    pub(crate) id: u32,
    pub(crate) unique: u64,
}

impl Filesystem {
    /// The mount a node on this filesystem is on, as `statx` names it: the
    /// volume's and the entropy device's are in [`MOUNTS`]; every other is
    /// one of the kernel's internal mounts (`kern_mount`), in no namespace,
    /// so `statmount` of it is `ENOENT`. Their ids are the ones boot hands
    /// them on the pinned 6.8.0-139 build (read live), fixed like the
    /// volume's.
    pub(crate) fn mount(self) -> MountIds {
        let internal = |id: u32, unique: u64| MountIds {
            id,
            unique: MNT_UNIQUE_ID_BASE + unique,
        };
        match self {
            Filesystem::Volume => MOUNTS[0].ids(),
            Filesystem::Devtmpfs => MOUNTS[1].ids(),
            Filesystem::Nsfs => internal(3, 4),
            Filesystem::Sockfs => internal(9, 10),
            Filesystem::Pipefs => internal(15, 17),
            Filesystem::AnonInodefs => internal(16, 18),
            Filesystem::Mqueue => internal(22, 24),
        }
    }

    /// Whether the filesystem records a birth time (`STATX_BTIME`): ext4
    /// and tmpfs do; the pseudo-filesystems' `getattr` fills none.
    fn has_btime(self) -> bool {
        match self {
            Filesystem::Volume | Filesystem::Devtmpfs => true,
            Filesystem::Pipefs
            | Filesystem::Sockfs
            | Filesystem::AnonInodefs
            | Filesystem::Mqueue
            | Filesystem::Nsfs => false,
        }
    }

    /// The filesystem a `PATINA_FS_*` node is on (`fs_device`'s mapping).
    fn of_node(fs: u32) -> Filesystem {
        match fs {
            PATINA_FS_PIPEFS => Filesystem::Pipefs,
            PATINA_FS_SOCKFS => Filesystem::Sockfs,
            crate::PATINA_FS_NSFS => Filesystem::Nsfs,
            _ => Filesystem::Volume,
        }
    }
}

/// `STATX_BTIME`, `STATX_MNT_ID`, `STATX_MNT_ID_UNIQUE`.
const STATX_BTIME: u32 = 0x0800;
const STATX_MNT_ID: u32 = 0x1000;
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

/// What `vfs_statx` adds to the basic statistics of a node on the
/// `PATINA_FS_*` filesystem `fs`, asked for `mask`: the mount id, whatever
/// was asked (the unique one when `STATX_MNT_ID_UNIQUE` is asked for, else
/// the small one), and `STATX_BTIME` when asked for and the filesystem
/// records one. The mask bits, and the mount id.
pub(crate) fn statx_extra(fs: u32, mask: u32) -> (u32, u64) {
    let filesystem = Filesystem::of_node(fs);
    let mount = filesystem.mount();
    let btime = if mask & STATX_BTIME != 0 && filesystem.has_btime() {
        STATX_BTIME
    } else {
        0
    };
    if mask & STATX_MNT_ID_UNIQUE != 0 {
        (btime | STATX_MNT_ID_UNIQUE, mount.unique)
    } else {
        (btime | STATX_MNT_ID, u64::from(mount.id))
    }
}

/// The C `statx`'s [`statx_extra`]: the mask bits to add; the mount id is
/// written to `mount_id`.
///
/// # Safety
/// `mount_id` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_statx_extra(fs: u32, mask: u32, mount_id: *mut u64) -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (bits, id) = statx_extra(fs, mask);
    // SAFETY: writable per this function's contract.
    unsafe { mount_id.write(id) };
    bits
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
            Some(_) => Ok(Filesystem::Volume),
            None => Err(EBADF),
        },
        FdKind::Socket => Ok(Filesystem::Sockfs),
        // 6.8's pidfd is an anonymous inode too (pidfs came in 6.9).
        FdKind::EventFd
        | FdKind::TimerFd
        | FdKind::SignalFd
        | FdKind::Epoll
        | FdKind::Pidfd
        | FdKind::LandlockRuleset
        | FdKind::Userfaultfd => Ok(Filesystem::AnonInodefs),
        FdKind::Namespace | FdKind::NamespacePath => Ok(Filesystem::Nsfs),
        FdKind::MessageQueue => Ok(Filesystem::Mqueue),
        FdKind::Urandom => Ok(Filesystem::Devtmpfs),
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => Err(EBADF),
    }
}

/// The block size of the superblock a descriptor's node is on
/// (`FIGETBSZ`): `statfs`'s `f_bsize`.
pub(crate) fn block_size(raw_fd: c_int) -> Result<i32, c_int> {
    descriptor_filesystem(raw_fd).map(|filesystem| filesystem.describe().f_bsize as i32)
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
        Ok(resolved) if crate::nsfs::entry_at(&resolved.path).is_some() => {
            copy_out(Filesystem::Nsfs.describe(), out)
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

/// A mount of the virtual machine's one mount namespace, as `statmount(2)`
/// and `listmount(2)` describe it. Every mount is reachable from the
/// caller's root (which never moves: `chroot` is refused), so none is
/// hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mount {
    /// `mnt_id`, the small id `statx`'s `STATX_MNT_ID` reports.
    pub(crate) id: u32,
    /// `mnt_id_unique`, the 64-bit id `STATX_MNT_ID_UNIQUE` reports and
    /// `statmount`/`listmount` take.
    pub(crate) unique: u64,
    /// The index in [`MOUNTS`] of the mount it is mounted on; the
    /// namespace's root is its own parent.
    parent: usize,
    filesystem: Filesystem,
    /// The mount's root within its filesystem (`mnt_root`).
    pub(crate) root: &'static str,
    /// Where it is mounted, from the caller's root.
    pub(crate) point: &'static str,
    /// `MOUNT_ATTR_*` (`relatime` is 0).
    pub(crate) attr: u64,
}

/// 6.8's first unique mount id is one past this (`mnt_id_ctr`, `1 << 32`;
/// 6.11 moved it to `1 << 31`).
const MNT_UNIQUE_ID_BASE: u64 = 1 << 32;
/// `MOUNT_ATTR_NOSUID`.
const MOUNT_ATTR_NOSUID: u64 = 0x2;

/// The virtual machine's mounts, in the order they were made (so in unique
/// id order, the order `listmount` walks): the volume at `/`, the
/// namespace's root; and the entropy device, a bind of devtmpfs's
/// `urandom` node onto `/dev/urandom` (what `statfs` reports it on, and the
/// crossing `RESOLVE_NO_XDEV` refuses). The kernel's internal mounts
/// (pipefs, sockfs, anon_inodefs, the IPC namespace's mqueue) are in no
/// namespace, as in the kernel.
pub(crate) const MOUNTS: [Mount; 2] = [
    Mount {
        id: 1,
        unique: MNT_UNIQUE_ID_BASE + 1,
        parent: 0,
        filesystem: Filesystem::Volume,
        root: "/",
        point: "/",
        attr: 0,
    },
    Mount {
        id: 2,
        unique: MNT_UNIQUE_ID_BASE + 2,
        parent: 0,
        filesystem: Filesystem::Devtmpfs,
        root: "/urandom",
        point: paths::URANDOM,
        attr: MOUNT_ATTR_NOSUID,
    },
];

/// The mount every node on the volume is on.
pub(crate) const ROOT_MOUNT: Mount = MOUNTS[0];

impl Mount {
    /// Its ids.
    pub(crate) const fn ids(&self) -> MountIds {
        MountIds {
            id: self.id,
            unique: self.unique,
        }
    }

    /// The mount it is mounted on.
    pub(crate) fn parent(&self) -> &'static Mount {
        &MOUNTS[self.parent]
    }

    /// Its superblock's device.
    pub(crate) fn device(&self) -> (u32, u32) {
        self.filesystem.device()
    }

    /// Its superblock's magic (`statfs`'s `f_type`).
    pub(crate) fn magic(&self) -> u64 {
        self.filesystem.describe().f_type as u64
    }

    /// Its filesystem's type name.
    pub(crate) fn fs_type(&self) -> &'static str {
        self.filesystem
            .registered_name()
            .expect("a mounted filesystem has a registered type")
    }
}

/// The filesystem types the virtual kernel registers, in the order 6.8
/// registers them at boot (the order the pinned host's `/proc/filesystems`
/// lists them in): each filesystem a node can be on that has a registered
/// type, and nothing else. procfs, whose `/proc/self/ns` links the model
/// answers, is left out: no node the model keeps is on it (a namespace
/// file opens an nsfs inode), and the kernel registers many more types than
/// the model has (tmpfs, sysfs, proc, …), which a caller listing them finds
/// missing either way.
#[cfg(target_arch = "x86_64")]
const REGISTERED: [Filesystem; 5] = [
    Filesystem::Devtmpfs,
    Filesystem::Sockfs,
    Filesystem::Pipefs,
    Filesystem::Volume,
    Filesystem::Mqueue,
];

/// `sysfs(2)` (fs/filesystems.c, `CONFIG_SYSFS_SYSCALL`, which the pinned
/// kernel builds; x86_64 only), over [`REGISTERED`]. `option` is an `int`:
/// 1 maps the type named at `arg1` to its index (`getname`: `EFAULT`,
/// `ENAMETOOLONG`, `ENOENT` for an empty name; `EINVAL` for one no type
/// has), 2 copies the name at index `arg1` (an `unsigned int`) to `arg2`
/// (`EINVAL` past the last, then `EFAULT`), 3 answers how many there are;
/// any other option is `EINVAL`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn sysfs(option: u64, arg1: u64, arg2: u64) -> i64 {
    let einval = -i64::from(EINVAL);
    let names = REGISTERED.map(|filesystem| {
        filesystem
            .registered_name()
            .expect("a registered filesystem has a type name")
    });
    match option as i32 {
        1 => match crate::uaccess::read_name(arg1 as usize) {
            Ok(name) => names
                .iter()
                .position(|registered| registered.as_bytes() == name)
                .map_or(einval, |index| index as i64),
            Err(errno) => -i64::from(errno),
        },
        2 => match names.get(arg1 as u32 as usize) {
            None => einval,
            Some(name) => {
                let mut bytes = name.as_bytes().to_vec();
                bytes.push(0);
                match crate::uaccess::write_bytes(arg2 as usize, &bytes) {
                    Ok(()) => 0,
                    Err(errno) => -i64::from(errno),
                }
            }
        },
        3 => names.len() as i64,
        _ => einval,
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

    /// Every filesystem a node can be on is registered once, but the
    /// internal anon_inodefs, and `sysfs(2)` walks exactly that list.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sysfs_lists_each_registered_filesystem_once() {
        for filesystem in Filesystem::ALL {
            let listed = REGISTERED.iter().filter(|r| **r == filesystem).count();
            let expected = usize::from(filesystem.registered_name().is_some());
            assert_eq!(listed, expected, "{filesystem:?}");
        }
        assert_eq!(sysfs(3, 0, 0), REGISTERED.len() as i64);
        let einval = -i64::from(EINVAL);
        for (index, filesystem) in REGISTERED.iter().enumerate() {
            let mut name = [0xffu8; 16];
            assert_eq!(sysfs(2, index as u64, name.as_mut_ptr() as u64), 0);
            let name = std::ffi::CStr::from_bytes_until_nul(&name).unwrap();
            assert_eq!(name.to_str().ok(), filesystem.registered_name());
            assert_eq!(sysfs(1, name.as_ptr() as u64, 0), index as i64);
        }
        // The index is an `unsigned int`: the upper half of the word is not read.
        let mut name = [0u8; 16];
        assert_eq!(sysfs(2, 1 << 32, name.as_mut_ptr() as u64), 0);
        assert_eq!(
            sysfs(2, REGISTERED.len() as u64, name.as_mut_ptr() as u64),
            einval
        );
        assert_eq!(sysfs(1, c"anon_inodefs".as_ptr() as u64, 0), einval);
        assert_eq!(sysfs(1, c"".as_ptr() as u64, 0), -i64::from(ENOENT));
        assert_eq!(sysfs(1, 0, 0), -i64::from(EFAULT));
        assert_eq!(sysfs(2, 0, 0), -i64::from(EFAULT));
        // The option is an `int`: the upper half of the word is not read.
        assert_eq!(sysfs(3 | 1 << 32, 0, 0), REGISTERED.len() as i64);
        assert_eq!(sysfs(0, 0, 0), einval);
    }

    /// The mount table agrees with what `statfs` says a path is on: the
    /// volume at the root, the device on devtmpfs; ids ascend in table
    /// order, and every mount hangs off the root.
    #[test]
    fn the_mounts_are_what_statfs_reports() {
        assert_eq!(ROOT_MOUNT.parent(), &ROOT_MOUNT);
        assert_eq!(ROOT_MOUNT.point, "/");
        for pair in MOUNTS.windows(2) {
            assert!(pair[0].id < pair[1].id && pair[0].unique < pair[1].unique);
        }
        for mount in &MOUNTS {
            assert!(mount.unique > MNT_UNIQUE_ID_BASE, "{mount:?}");
            assert_eq!(mount.parent().unique, ROOT_MOUNT.unique, "{mount:?}");
            let mut out = KernelStatfs::default();
            let point = std::ffi::CString::new(mount.point).unwrap();
            // SAFETY: a valid path and a writable buffer.
            if mount.filesystem != Filesystem::Volume {
                assert_eq!(unsafe { patina_statfs(point.as_ptr(), &mut out) }, 0);
                assert_eq!(out, mount.filesystem.describe(), "{mount:?}");
            }
            assert_eq!(mount.magic(), mount.filesystem.describe().f_type as u64);
        }
    }

    /// Each filesystem's mount, as `statx` names it: the namespace's own
    /// are the table's; every internal one is distinct and unknown to
    /// `statmount`/`listmount` (`ENOENT`).
    #[test]
    fn statx_names_each_filesystem_s_own_mount() {
        for filesystem in Filesystem::ALL {
            let mount = filesystem.mount();
            match MOUNTS.iter().find(|listed| listed.filesystem == filesystem) {
                Some(listed) => assert_eq!(mount, listed.ids(), "{filesystem:?}"),
                None => assert!(
                    MOUNTS
                        .iter()
                        .all(|listed| listed.id != mount.id && listed.unique != mount.unique),
                    "{filesystem:?}"
                ),
            }
            assert!(mount.unique > MNT_UNIQUE_ID_BASE, "{filesystem:?}");
            for other in Filesystem::ALL.iter().filter(|other| **other != filesystem) {
                let theirs = other.mount();
                assert!(
                    mount.id != theirs.id && mount.unique != theirs.unique,
                    "{filesystem:?}"
                );
            }
        }
        assert_eq!(
            statx_extra(PATINA_FS_VOLUME, STATX_MNT_ID_UNIQUE),
            (STATX_MNT_ID_UNIQUE, ROOT_MOUNT.unique)
        );
        assert_eq!(
            statx_extra(PATINA_FS_VOLUME, STATX_BTIME),
            (STATX_BTIME | STATX_MNT_ID, u64::from(ROOT_MOUNT.id))
        );
        assert_eq!(statx_extra(PATINA_FS_PIPEFS, STATX_BTIME).0, STATX_MNT_ID);
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
