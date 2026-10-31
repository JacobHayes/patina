//! What `statfs(2)`/`fstatfs(2)`/`ustat(2)` report: the filesystem a path or a
//! descriptor is on, described the way the kernel describes it.
//!
//! Every entry a path can name is on ONE deterministic volume, an ext4-like
//! filesystem on block device 8:1 whose description is a constant (so it is
//! the same on record and replay and on every host): the shared
//! [`VOLUME`] geometry (4 KiB blocks, fixed block and inode counts),
//! `NAME_MAX` names, and `f_flags` as
//! `calculate_f_flags` builds them — `ST_VALID` always, plus the mount's
//! `relatime`, the atime policy the filesystem stamps by. A descriptor with no
//! entry on the volume is on one of the kernel's pseudo-filesystems, which
//! answer through `simple_statfs`: an anonymous pipe on pipefs, a socket on
//! sockfs, an eventfd, signalfd or epoll instance on
//! anon_inodefs. The memory devices (`crate::memdev`) are each on a bind of
//! devtmpfs (a tmpfs), described by constants like the volume; the procfs
//! entries the model answers (`crate::procfs`) are on procfs, mounted at
//! `/proc`, which answers through `simple_statfs` too. Every `f_fsid`
//! is derived from the filesystem's device. This is the Linux description;
//! macOS describes the same volume as APFS (`posix/fs/darwin_volume.rs`).

#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::{c_char, c_int};

#[cfg(target_arch = "x86_64")]
use crate::EINVAL;
use crate::fdtable::FdKind;
use crate::fs::VOLUME;
use crate::memdev::MemDevice;
use crate::{
    EBADF, EFAULT, ENOENT, PATINA_FS_PIPEFS, PATINA_FS_SOCKFS, PATINA_FS_VOLUME, fs_device,
    path_from_c, paths, resolve_fd, set_errno, thread,
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

mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::KernelStatfs {
        f_type: i64,
        f_bsize: i64,
        f_blocks: u64,
        f_bfree: u64,
        f_bavail: u64,
        f_files: u64,
        f_ffree: u64,
        f_fsid: [i32; 2],
        f_namelen: i64,
        f_frsize: i64,
        f_flags: i64,
        f_spare: [i64; 4],
    });
    crate::plain!(super::KernelUstat {
        f_tfree: i32,
        pad1: u32,
        f_tinode: u64,
        f_fname: [u8; 6],
        f_fpack: [u8; 6],
        tail: u32,
    });
}

/// linux/magic.h.
const EXT4_SUPER_MAGIC: i64 = 0xEF53;
const PIPEFS_MAGIC: i64 = 0x5049_5045;
const SOCKFS_MAGIC: i64 = 0x534F_434B;
const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const NSFS_MAGIC: i64 = 0x6e73_6673;
const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// `statfs(2)` `f_flags`: the answer is valid (`ST_VALID`, set by
/// `calculate_f_flags` on every answer) and the mount's atime policy.
const ST_VALID: i64 = 0x0020;
const ST_NOSUID: i64 = 0x0002;
const ST_NODEV: i64 = 0x0004;
const ST_NOEXEC: i64 = 0x0008;
const ST_RELATIME: i64 = 0x1000;

/// `NAME_MAX`.
const NAME_MAX: i64 = 255;

/// The anonymous device devtmpfs is on.
const DEVTMPFS_DEVICE: (u32, u32) = (0, 5);

/// A filesystem a node can be on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Filesystem {
    Volume,
    Pipefs,
    Sockfs,
    AnonInodefs,
    Devtmpfs,
    Nsfs,
    Proc,
}

impl Filesystem {
    #[cfg(any(target_arch = "x86_64", test))]
    const ALL: [Filesystem; 7] = [
        Filesystem::Volume,
        Filesystem::Pipefs,
        Filesystem::Sockfs,
        Filesystem::AnonInodefs,
        Filesystem::Devtmpfs,
        Filesystem::Nsfs,
        Filesystem::Proc,
    ];

    fn device(self) -> (u32, u32) {
        match self {
            Filesystem::Volume => fs_device(PATINA_FS_VOLUME),
            Filesystem::Pipefs => fs_device(PATINA_FS_PIPEFS),
            Filesystem::Sockfs => fs_device(PATINA_FS_SOCKFS),
            Filesystem::AnonInodefs => fs_device(crate::PATINA_FS_ANON_INODE),
            Filesystem::Devtmpfs => DEVTMPFS_DEVICE,
            Filesystem::Nsfs => fs_device(crate::PATINA_FS_NSFS),
            Filesystem::Proc => fs_device(crate::PATINA_FS_PROC),
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
                f_bsize: i64::from(VOLUME.block_size),
                f_blocks: VOLUME.blocks,
                f_bfree: VOLUME.free_blocks,
                f_bavail: VOLUME.free_blocks,
                f_files: VOLUME.files,
                f_ffree: VOLUME.free_files,
                f_fsid: self.fsid(),
                f_namelen: NAME_MAX,
                f_frsize: i64::from(VOLUME.block_size),
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
                // Its nodes: the memory devices and the multiplexer.
                f_ffree: (1 << 18) - MemDevice::ALL.len() as u64 - 1,
                f_fsid: self.fsid(),
                f_namelen: NAME_MAX,
                f_frsize: crate::PAGE_SIZE as i64,
                f_flags: ST_VALID | ST_NOSUID | ST_RELATIME,
                f_spare: [0; 4],
            },
            // `simple_statfs`, on the mount at `/proc`.
            Filesystem::Proc => KernelStatfs {
                f_type: PROC_SUPER_MAGIC,
                f_bsize: crate::PAGE_SIZE as i64,
                f_fsid: self.fsid(),
                f_namelen: NAME_MAX,
                f_frsize: crate::PAGE_SIZE as i64,
                f_flags: ST_VALID | ST_NOSUID | ST_NODEV | ST_NOEXEC | ST_RELATIME,
                ..KernelStatfs::default()
            },
            Filesystem::Pipefs
            | Filesystem::Sockfs
            | Filesystem::AnonInodefs
            | Filesystem::Nsfs => KernelStatfs {
                f_type: match self {
                    Filesystem::Pipefs => PIPEFS_MAGIC,
                    Filesystem::Sockfs => SOCKFS_MAGIC,
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
    /// volume's and devtmpfs's (`/dev/urandom`'s bind; each memory device and
    /// the multiplexer are bound at their own paths, [`node_mount`]) are in
    /// [`MOUNTS`]; every other is
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
            Filesystem::Proc => MOUNTS[3].ids(),
            Filesystem::Nsfs => internal(3, 4),
            Filesystem::Sockfs => internal(9, 10),
            Filesystem::Pipefs => internal(15, 17),
            Filesystem::AnonInodefs => internal(16, 18),
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
            | Filesystem::Nsfs
            | Filesystem::Proc => false,
        }
    }

    /// The superblock's block size (`s_blocksize`, what `FIGETBSZ`
    /// answers): `statfs`'s `f_bsize`, but procfs's 1 KiB,
    /// which `simple_statfs` does not report.
    fn block_size(self) -> i32 {
        match self {
            Filesystem::Proc => 1024,
            _ => self.describe().f_bsize as i32,
        }
    }

    /// The filesystem a `PATINA_FS_*` node is on (`fs_device`'s mapping).
    fn of_node(fs: u32) -> Filesystem {
        match fs {
            PATINA_FS_PIPEFS => Filesystem::Pipefs,
            PATINA_FS_SOCKFS => Filesystem::Sockfs,
            crate::PATINA_FS_NSFS => Filesystem::Nsfs,
            crate::PATINA_FS_DEVTMPFS => Filesystem::Devtmpfs,
            crate::PATINA_FS_ANON_INODE => Filesystem::AnonInodefs,
            crate::PATINA_FS_PROC | crate::PATINA_FS_PROC_OWN => Filesystem::Proc,
            _ => Filesystem::Volume,
        }
    }
}

/// `STATX_BTIME`, `STATX_MNT_ID`, `STATX_MNT_ID_UNIQUE`.
const STATX_BTIME: u32 = 0x0800;
const STATX_MNT_ID: u32 = 0x1000;
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

/// The mount the node `ino` on the `PATINA_FS_*` filesystem `fs` is on: a
/// devtmpfs node is bound at its own path, so its mount is its bind's.
fn node_mount(fs: u32, ino: u64) -> MountIds {
    if fs == crate::PATINA_FS_DEVTMPFS
        && let Some(device) = MemDevice::of_ino(ino)
        && let Some(bind) = MOUNTS.iter().find(|mount| mount.point == device.path())
    {
        return bind.ids();
    }
    Filesystem::of_node(fs).mount()
}

/// What `vfs_statx` adds to the basic statistics of the node `ino` on the
/// `PATINA_FS_*` filesystem `fs`, asked for `mask`: the mount id, whatever
/// was asked (the unique one when `STATX_MNT_ID_UNIQUE` is asked for, else
/// the small one), and `STATX_BTIME` when asked for and the filesystem
/// records one. The mask bits, and the mount id.
pub(crate) fn statx_extra(fs: u32, ino: u64, mask: u32) -> (u32, u64) {
    let filesystem = Filesystem::of_node(fs);
    let mount = node_mount(fs, ino);
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

#[unsafe(no_mangle)]
/// The C `statx`'s [`statx_extra`]: the mask bits to add; the mount id is
/// written to `mount_id`.
///
/// # Safety
/// `mount_id` must be writable.
pub unsafe extern "C" fn patina_statx_extra(
    fs: u32,
    ino: u64,
    mask: u32,
    mount_id: *mut u64,
) -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let (bits, id) = statx_extra(fs, ino, mask);
    // SAFETY: writable per this function's contract.
    unsafe { mount_id.write(id) };
    bits
}

/// The filesystem a descriptor is on (`fdget_raw`: an `O_PATH` descriptor
/// names its entry on the volume). The standard streams are pipes, on
/// pipefs.
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
        | FdKind::Inotify
        | FdKind::SignalFd
        | FdKind::Epoll
        | FdKind::Pidfd => Ok(Filesystem::AnonInodefs),
        FdKind::Namespace | FdKind::NamespacePath => Ok(Filesystem::Nsfs),
        FdKind::MemDevice => Ok(Filesystem::Devtmpfs),
        FdKind::Proc | FdKind::ProcDir => Ok(Filesystem::Proc),
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => Ok(Filesystem::Pipefs),
    }
}

/// The block size of the superblock a descriptor's node is on
/// (`FIGETBSZ`): `statfs`'s `f_bsize`.
pub(crate) fn block_size(raw_fd: c_int) -> Result<i32, c_int> {
    descriptor_filesystem(raw_fd).map(Filesystem::block_size)
}

/// Copy a description out, as `do_statfs_native` does last: a NULL buffer is
/// `EFAULT`, after everything else has been judged.
fn copy_out(description: KernelStatfs, out: *mut KernelStatfs) -> crate::abi::SysResult<()> {
    if out.is_null() {
        return Err(crate::abi::failed(EFAULT));
    }
    // SAFETY: `out` is non-null and writable per the C ABI contract.
    unsafe { crate::plain::store(out, description) };
    set_errno(0);
    Ok(())
}

#[unsafe(no_mangle)]
/// `statfs(2)`: the filesystem `path` (a trailing symlink followed) is on.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string; `out`, when
/// non-null, to a writable `struct statfs`.
pub unsafe extern "C" fn patina_statfs(path: *const c_char, out: *mut KernelStatfs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The prefixed C ABI contract guarantees a readable path string.
    unsafe { statfs(path, out) }.map_or(-1, |_| 0)
}

/// Resolve a path and return its modeled filesystem description.
///
/// # Safety
/// `path` must point to a valid NUL-terminated UTF-8 string; `out`, when
/// non-null, must point to writable `KernelStatfs` storage.
pub(crate) unsafe fn statfs(
    path: *const c_char,
    out: *mut KernelStatfs,
) -> crate::abi::SysResult<()> {
    // SAFETY: This export's C ABI contract guarantees a readable path string.
    let path = match unsafe { path_from_c(path) } {
        Ok(path) => path,
        Err(errno) => return Err(crate::abi::failed(errno)),
    };
    match paths::resolve(paths::AT_FDCWD, &path, 0) {
        Ok(paths::Resolution::Volume(resolved)) if resolved.metadata.is_some() => {
            copy_out(Filesystem::Volume.describe(), out)
        }
        Ok(paths::Resolution::Volume(_)) => Err(crate::abi::failed(ENOENT)),
        Ok(paths::Resolution::Virtual(paths::Virtual::MemDevice(_))) => {
            copy_out(Filesystem::Devtmpfs.describe(), out)
        }
        Ok(paths::Resolution::Virtual(paths::Virtual::Namespace(_))) => {
            copy_out(Filesystem::Nsfs.describe(), out)
        }
        Ok(paths::Resolution::Virtual(paths::Virtual::Ptmx)) => {
            copy_out(Filesystem::Devtmpfs.describe(), out)
        }
        Ok(paths::Resolution::Virtual(entry @ paths::Virtual::Tty)) => {
            entry.unmodeled("the filesystem statistics")
        }
        Ok(paths::Resolution::Virtual(paths::Virtual::Proc(_))) => {
            copy_out(Filesystem::Proc.describe(), out)
        }
        Err(errno) => Err(crate::abi::failed(errno)),
    }
}

/// Describe the modeled filesystem a descriptor is on.
///
/// # Safety
/// `out`, when non-null, must point to writable `KernelStatfs` storage.
pub(crate) unsafe fn fstatfs(raw_fd: c_int, out: *mut KernelStatfs) -> crate::abi::SysResult<()> {
    match descriptor_filesystem(raw_fd) {
        Ok(filesystem) => copy_out(filesystem.describe(), out),
        Err(errno) => Err(crate::abi::failed(errno)),
    }
}

/// The anonymous inode's number on anon_inodefs: a virtual constant. Boot
/// allocates it (`anon_inode_init`, from `get_next_ino`'s per-CPU batches),
/// so the number depends on boot order, CPU count and configuration; this is
/// the pinned host's reading when it was written, and any number would do
/// (the conformance events compare inode numbers relatively).
const ANON_INODE_INO: u64 = 69;

/// Whether a descriptor of `kind` is a file on 6.8's one anonymous inode
/// (`anon_inode_getfile`/`anon_inode_getfd`: `[eventfd]`, `[timerfd]`,
/// `[signalfd]`, `[eventpoll]`, `inotify`, `[pidfd]` — pidfs came in 6.9 —
/// and `[landlock-ruleset]`), every one of them the same inode.
pub(crate) fn on_anon_inode(kind: FdKind) -> bool {
    matches!(
        kind,
        FdKind::EventFd
            | FdKind::TimerFd
            | FdKind::SignalFd
            | FdKind::Epoll
            | FdKind::Inotify
            | FdKind::Pidfd
    )
}

/// The anonymous inode (`alloc_anon_inode`): root's `0600` with no file
/// type, one link, empty, on anon_inodefs; every time the instant boot made
/// it.
pub(crate) fn anon_inode_metadata() -> crate::PatinaMetadata {
    let made = crate::PatinaTimestamp::from_nanos(i128::from(crate::boot_instant()));
    crate::PatinaMetadata {
        kind: crate::PATINA_ENTRY_ANON,
        mode: 0o600,
        nlink: 1,
        fs: crate::PATINA_FS_ANON_INODE,
        rdev_major: 0,
        rdev_minor: 0,
        length: 0,
        blocks: 0,
        ino: ANON_INODE_INO,
        atime: made,
        mtime: made,
        ctime: made,
        btime: crate::PatinaTimestamp::default(),
    }
}

/// A mount of the virtual machine's one mount namespace: the ids `statx`
/// reports for a node on it, and where it is mounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mount {
    /// `mnt_id`, the small id `statx`'s `STATX_MNT_ID` reports.
    pub(crate) id: u32,
    /// `mnt_id_unique`, the 64-bit id `STATX_MNT_ID_UNIQUE` reports.
    pub(crate) unique: u64,
    filesystem: Filesystem,
    /// Where it is mounted, from the caller's root.
    pub(crate) point: &'static str,
}

/// 6.8's first unique mount id is one past this (`mnt_id_ctr`, `1 << 32`;
/// 6.11 moved it to `1 << 31`).
const MNT_UNIQUE_ID_BASE: u64 = 1 << 32;
/// The virtual machine's mounts, in the order they were made: the volume at `/`, the
/// namespace's root; `/dev/urandom`, a bind of devtmpfs's `urandom`
/// node onto `/dev/urandom` (what `statfs` reports it on, and the crossing
/// `RESOLVE_NO_XDEV` refuses); the pseudoterminal multiplexer, a bind of
/// devtmpfs's `ptmx` node onto `/dev/ptmx`, the same way; procfs at `/proc` (`nosuid,nodev,noexec`, as hosts mount it); and the
/// other memory devices' binds, `/dev/null`, `/dev/zero`, `/dev/random` and
/// (Linux has it) `/dev/full`, the same way as `/dev/urandom`'s. The
/// kernel's internal mounts (pipefs, sockfs, anon_inodefs, the IPC
/// namespace's mqueue) are in no namespace, as in the kernel.
pub(crate) const MOUNTS: [Mount; 8] = [
    Mount {
        id: 1,
        unique: MNT_UNIQUE_ID_BASE + 1,
        filesystem: Filesystem::Volume,
        point: "/",
    },
    Mount {
        id: 2,
        unique: MNT_UNIQUE_ID_BASE + 2,
        filesystem: Filesystem::Devtmpfs,
        point: MemDevice::Urandom.path(),
    },
    Mount {
        id: 4,
        unique: MNT_UNIQUE_ID_BASE + 3,
        filesystem: Filesystem::Devtmpfs,
        point: paths::PTMX,
    },
    Mount {
        id: 6,
        unique: MNT_UNIQUE_ID_BASE + 6,
        filesystem: Filesystem::Proc,
        point: crate::procfs::ROOT,
    },
    Mount {
        id: 7,
        unique: MNT_UNIQUE_ID_BASE + 7,
        filesystem: Filesystem::Devtmpfs,
        point: MemDevice::Null.path(),
    },
    Mount {
        id: 8,
        unique: MNT_UNIQUE_ID_BASE + 8,
        filesystem: Filesystem::Devtmpfs,
        point: MemDevice::Zero.path(),
    },
    Mount {
        id: 10,
        unique: MNT_UNIQUE_ID_BASE + 9,
        filesystem: Filesystem::Devtmpfs,
        point: MemDevice::Random.path(),
    },
    Mount {
        id: 11,
        unique: MNT_UNIQUE_ID_BASE + 11,
        filesystem: Filesystem::Devtmpfs,
        point: MemDevice::Full.path(),
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
}

/// The filesystem types the virtual kernel registers, in the order 6.8
/// registers them at boot (the order the pinned host's `/proc/filesystems`
/// lists them in). The kernel registers many more types than the
/// model has (tmpfs, sysfs, cgroup, …), which a caller listing them finds
/// missing.
#[cfg(target_arch = "x86_64")]
const REGISTERED: [&str; 7] = [
    "proc", "devtmpfs", "sockfs", "pipefs", "devpts", "ext4", "mqueue",
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
    let names = REGISTERED;
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
    pub pad1: u32,
    pub f_tinode: u64,
    pub f_fname: [u8; 6],
    pub f_fpack: [u8; 6],
    pub tail: u32,
}

/// Return the legacy free-block/inode view for a modeled block device.
///
/// # Safety
/// `out`, when non-null, must point to writable `KernelUstat` storage.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn ustat(dev: u32, out: *mut KernelUstat) -> crate::abi::SysResult<()> {
    let major = (dev & 0xfff00) >> 8;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    let Some(filesystem) = Filesystem::ALL
        .into_iter()
        .find(|filesystem| filesystem.device() == (major, minor))
    else {
        return Err(crate::abi::failed(EINVAL));
    };
    if out.is_null() {
        return Err(crate::abi::failed(EFAULT));
    }
    let description = filesystem.describe();
    // SAFETY: `out` is non-null and writable per the C ABI contract.
    unsafe {
        crate::plain::store(
            out,
            KernelUstat {
                f_tfree: description.f_bfree as i32,
                f_tinode: description.f_ffree,
                ..KernelUstat::default()
            },
        )
    };
    set_errno(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sysfs(2)` walks the registered types, by index and by name.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sysfs_lists_each_registered_filesystem_once() {
        assert_eq!(sysfs(3, 0, 0), REGISTERED.len() as i64);
        let einval = -i64::from(EINVAL);
        for (index, registered) in REGISTERED.iter().enumerate() {
            let mut name = [0xffu8; 16];
            assert_eq!(sysfs(2, index as u64, name.as_mut_ptr() as u64), 0);
            let name = std::ffi::CStr::from_bytes_until_nul(&name).unwrap();
            assert_eq!(name.to_str().ok(), Some(*registered));
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
    /// order.
    #[test]
    fn the_mounts_are_what_statfs_reports() {
        assert_eq!(ROOT_MOUNT.point, "/");
        for pair in MOUNTS.windows(2) {
            assert!(pair[0].id < pair[1].id && pair[0].unique < pair[1].unique);
        }
        for mount in &MOUNTS {
            assert!(mount.unique > MNT_UNIQUE_ID_BASE, "{mount:?}");
            let mut out = KernelStatfs::default();
            let point = std::ffi::CString::new(mount.point).unwrap();
            if mount.filesystem != Filesystem::Volume {
                // SAFETY: `point` is NUL-terminated and `out` is writable.
                assert_eq!(unsafe { patina_statfs(point.as_ptr(), &mut out) }, 0);
                assert_eq!(out, mount.filesystem.describe(), "{mount:?}");
            }
        }
        // The entropy device is on devtmpfs (a mount crossing to
        // `openat2(RESOLVE_NO_XDEV)`), not `ENOENT`.
        let mut out = KernelStatfs::default();
        // SAFETY: a valid path and a writable buffer.
        let answer = unsafe { patina_statfs(c"/dev/urandom".as_ptr(), &mut out) };
        assert_eq!(answer, 0);
        assert_eq!(out, Filesystem::Devtmpfs.describe());
        assert_eq!(out.f_type, TMPFS_MAGIC);
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
            statx_extra(PATINA_FS_VOLUME, 0, STATX_MNT_ID_UNIQUE),
            (STATX_MNT_ID_UNIQUE, ROOT_MOUNT.unique)
        );
        assert_eq!(
            statx_extra(PATINA_FS_VOLUME, 0, STATX_BTIME),
            (STATX_BTIME | STATX_MNT_ID, u64::from(ROOT_MOUNT.id))
        );
        assert_eq!(
            statx_extra(PATINA_FS_PIPEFS, 0, STATX_BTIME).0,
            STATX_MNT_ID
        );
    }

    /// Each memory device is on its own bind: `statx` names the mount
    /// listed at its path.
    #[test]
    fn each_memory_device_is_on_the_bind_at_its_path() {
        let mut seen = Vec::new();
        for device in MemDevice::ALL {
            let node = device.metadata();
            let (_, unique) = statx_extra(node.fs, node.ino, STATX_MNT_ID_UNIQUE);
            let bind = MOUNTS
                .iter()
                .find(|mount| mount.point == device.path())
                .expect("a bind at the device's path");
            assert_eq!(unique, bind.unique, "{device:?}");
            seen.push(unique);
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), MemDevice::ALL.len());
    }
}
