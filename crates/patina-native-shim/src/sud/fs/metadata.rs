//! Filesystem metadata and stat-family syscall encoding.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---- Metadata (fstat / newfstatat / statx) ----

/// The metadata record the runtime fills (`struct patina_metadata`): the same
/// one the C stat family normalizes. `mode` carries the permission bits
/// (`0o7777`) WITHOUT the file-type bits; `kind` carries those, and `st_mode`
/// is the two ORed together — see [`stat_mode`].
pub(in crate::sud) type StatValues = PatinaMetadata;

const fn empty_metadata() -> PatinaMetadata {
    PatinaMetadata {
        kind: 0,
        mode: 0,
        nlink: 0,
        fs: 0,
        rdev_major: 0,
        rdev_minor: 0,
        length: 0,
        blocks: 0,
        ino: 0,
        atime: PatinaTimestamp { sec: 0, nsec: 0 },
        mtime: PatinaTimestamp { sec: 0, nsec: 0 },
        ctime: PatinaTimestamp { sec: 0, nsec: 0 },
        btime: PatinaTimestamp { sec: 0, nsec: 0 },
    }
}

/// The virtual volume's block size, the same 4 KiB the statfs profile
/// reports (`st_blksize`); `st_blocks` is the record's own allocation.
const STAT_BLOCK_SIZE: u64 = 4096;

/// `st_blksize`: the volume's block, but for a devpts node, whose inode
/// takes its superblock's 1 KiB (`devpts_fill_super`). Byte for byte with
/// the C `patina_stat_blksize`.
fn stat_blksize(values: &StatValues) -> u64 {
    if values.fs == crate::PATINA_FS_DEVPTS {
        1024
    } else {
        STAT_BLOCK_SIZE
    }
}

/// The one virtual volume's mount id (`stx_mnt_id`), the C
/// `PATINA_STATX_MNT_ID`.
pub(super) const STATX_MNT_ID_VALUE: u64 = crate::volume::ROOT_MOUNT.id as u64;

/// `st_mode`: the entry's file-type bits ORed with its permission bits, byte
/// for byte with the C `patina_stat_mode` (the anonymous inode has none).
pub(in crate::sud) fn stat_mode(values: &StatValues) -> u32 {
    let kind = match values.kind {
        PATINA_ENTRY_ANON => 0,
        PATINA_ENTRY_DIRECTORY => S_IFDIR,
        PATINA_ENTRY_SYMLINK => S_IFLNK,
        PATINA_ENTRY_FIFO => S_IFIFO,
        PATINA_ENTRY_SOCKET => S_IFSOCK,
        PATINA_ENTRY_CHAR => S_IFCHR,
        _ => S_IFREG,
    };
    kind | (values.mode & 0o7777)
}

/// The owner `stat` reports, the one the C door reports too
/// ([`crate::node_owner`]).
pub(crate) fn stat_owner(values: &StatValues) -> (u32, u32) {
    crate::node_owner(values.fs)
}

/// The kernel's `new_encode_dev`: the 32-bit device word `struct stat` carries.
fn encode_dev((major, minor): (u32, u32)) -> u64 {
    u64::from((minor & 0xff) | (major << 8) | ((minor & !0xff) << 12))
}

/// The kernel `struct stat` for the `fstat`/`newfstatat` syscalls. The layout is
/// arch-specific (x86_64 vs the arm64 generic layout); the fields the C
/// `fill_stat` sets are populated (the device of the node's filesystem, mode,
/// link count, inode, size, the owner from the one modeled identity, the three
/// timestamps, the block geometry, a device node's `st_rdev`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::sud) struct KernelStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    pub(super) st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    __unused: [i64; 3],
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::sud) struct KernelStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    __pad1: u64,
    pub(super) st_size: i64,
    st_blksize: i32,
    __pad2: i32,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: u64,
    st_mtime: i64,
    st_mtime_nsec: u64,
    st_ctime: i64,
    st_ctime_nsec: u64,
    __unused: [u32; 2],
}

impl KernelStat {
    fn from_values(values: &StatValues) -> Self {
        Self {
            st_dev: encode_dev(crate::fs_device(values.fs)),
            st_rdev: encode_dev((values.rdev_major, values.rdev_minor)),
            st_mode: stat_mode(values),
            st_nlink: values.nlink as _,
            st_ino: values.ino,
            st_size: values.length as i64,
            st_uid: stat_owner(values).0,
            st_gid: stat_owner(values).1,
            st_blksize: stat_blksize(values) as _,
            st_blocks: values.blocks as i64,
            st_atime: values.atime.sec,
            st_atime_nsec: values.atime.nsec as _,
            st_mtime: values.mtime.sec,
            st_mtime_nsec: values.mtime.nsec as _,
            st_ctime: values.ctime.sec,
            st_ctime_nsec: values.ctime.nsec as _,
            ..Self::default()
        }
    }
}

pub(in crate::sud) fn fd_stat_values(fd: c_int) -> Result<StatValues, i64> {
    let mut v = empty_metadata();
    // SAFETY: the out-pointer is writable local storage.
    let rc = unsafe { crate::fs::patina_fd_metadata_full(fd, &mut v) };
    if rc != 0 {
        return Err(-(crate::environment::patina_errno() as i64));
    }
    Ok(v)
}

/// The metadata of what `(dirfd, path)` resolves to, through the one by-path
/// metadata entry the C stat family calls (`flags` are `PATINA_RESOLVE_*`).
pub(in crate::sud) fn path_stat_values(
    dirfd: i64,
    path: u64,
    flags: u32,
) -> Result<StatValues, i64> {
    let path = guest_path(path)?;
    let mut v = empty_metadata();
    // SAFETY: `path` is a valid guest C string; the out-pointer is local storage.
    let rc = unsafe { crate::fs::patina_metadata_at(dirfd as c_int, path, flags, &mut v) };
    if rc != 0 {
        return Err(-(crate::environment::patina_errno() as i64));
    }
    Ok(v)
}

pub(in crate::sud) fn write_kernel_stat(values: &StatValues, out: u64) -> i64 {
    if out == 0 {
        return -EINVAL;
    }
    // SAFETY: `out` is the guest's `struct stat` storage.
    unsafe { (out as *mut KernelStat).write(KernelStat::from_values(values)) };
    0
}

pub(in crate::sud) fn sys_fstat(fd: i64, statbuf: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // A directory fd is an ordinary deterministic-filesystem fd, so the shared
    // descriptor-metadata entry already reports it as a directory.
    match fd_stat_values(fd as c_int) {
        Ok(values) => write_kernel_stat(&values, statbuf),
        Err(errno) => errno,
    }
}

/// The `*at` metadata flags the kernel's `vfs_statx` accepts for both
/// `newfstatat` and `statx` (the C `PATINA_STAT_AT_FLAGS`); any other bit is
/// `EINVAL`.
pub(in crate::sud) const STAT_AT_FLAGS: u64 =
    AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE;

/// Resolve the addressing forms the `*at` metadata rows accept onto the same
/// virtual metadata `stat` answers from, mirroring the C
/// `patina_stat_at_values`:
///
/// - `AT_EMPTY_PATH` with an empty path on a descriptor — the DESCRIPTOR's own
///   metadata (`File::metadata()` on Linux is exactly this);
/// - `AT_EMPTY_PATH` with an empty path on `AT_FDCWD` — the working directory;
/// - everything else — the resolved path, `AT_SYMLINK_NOFOLLOW` naming a
///   trailing symlink itself.
///
/// As in `vfs_statx`, the flags are judged before the descriptor, which the
/// kernel reads as an `int` and consults only to resolve a relative path.
pub(in crate::sud) fn stat_at_values(dirfd: i64, path: u64, flags: u64) -> Result<StatValues, i64> {
    if flags & !STAT_AT_FLAGS != 0 {
        return Err(-EINVAL);
    }
    let dirfd = dirfd as c_int;
    if dirfd != AT_FDCWD as c_int && is_empty_path(path, flags) {
        return fd_stat_values(dirfd);
    }
    path_stat_values(dirfd.into(), path, resolve_flags(flags))
}

pub(in crate::sud) fn sys_newfstatat(dirfd: i64, path: u64, statbuf: u64, flags: u64) -> i64 {
    match stat_at_values(dirfd, path, flags) {
        Ok(values) => write_kernel_stat(&values, statbuf),
        Err(errno) => errno,
    }
}

/// Kernel `struct statx_timestamp`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(in crate::sud) struct StatxTimestamp {
    pub(super) tv_sec: i64,
    pub(super) tv_nsec: u32,
    __reserved: i32,
}

/// Kernel `struct statx` (arch-independent).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::sud) struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    __spare3: [u64; 12],
}

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    #[cfg(target_arch = "x86_64")]
    crate::plain!(super::KernelStat {
        st_dev: u64,
        st_ino: u64,
        st_nlink: u64,
        st_mode: u32,
        st_uid: u32,
        st_gid: u32,
        __pad0: u32,
        st_rdev: u64,
        st_size: i64,
        st_blksize: i64,
        st_blocks: i64,
        st_atime: i64,
        st_atime_nsec: i64,
        st_mtime: i64,
        st_mtime_nsec: i64,
        st_ctime: i64,
        st_ctime_nsec: i64,
        __unused: [i64; 3],
    });

    #[cfg(target_arch = "aarch64")]
    crate::plain!(super::KernelStat {
        st_dev: u64,
        st_ino: u64,
        st_mode: u32,
        st_nlink: u32,
        st_uid: u32,
        st_gid: u32,
        st_rdev: u64,
        __pad1: u64,
        st_size: i64,
        st_blksize: i32,
        __pad2: i32,
        st_blocks: i64,
        st_atime: i64,
        st_atime_nsec: u64,
        st_mtime: i64,
        st_mtime_nsec: u64,
        st_ctime: i64,
        st_ctime_nsec: u64,
        __unused: [u32; 2],
    });

    crate::plain!(super::StatxTimestamp {
        tv_sec: i64,
        tv_nsec: u32,
        __reserved: i32,
    });
    crate::plain!(super::Statx {
        stx_mask: u32,
        stx_blksize: u32,
        stx_attributes: u64,
        stx_nlink: u32,
        stx_uid: u32,
        stx_gid: u32,
        stx_mode: u16,
        __spare0: u16,
        stx_ino: u64,
        stx_size: u64,
        stx_blocks: u64,
        stx_attributes_mask: u64,
        stx_atime: super::StatxTimestamp,
        stx_btime: super::StatxTimestamp,
        stx_ctime: super::StatxTimestamp,
        stx_mtime: super::StatxTimestamp,
        stx_rdev_major: u32,
        stx_rdev_minor: u32,
        stx_dev_major: u32,
        stx_dev_minor: u32,
        stx_mnt_id: u64,
        stx_dio_mem_align: u32,
        stx_dio_offset_align: u32,
        __spare3: [u64; 12],
    });
}

pub(in crate::sud) fn sys_statx(
    dirfd: i64,
    path: u64,
    flags: u64,
    flags_mask: u64,
    statxbuf: u64,
) -> i64 {
    // `do_statx` refuses both sync modes at once and the reserved mask bit
    // before anything else, and copies the answer out last.
    if flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE || flags_mask & STATX__RESERVED != 0 {
        return -EINVAL;
    }
    let values = match stat_at_values(dirfd, path, flags) {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    if statxbuf == 0 {
        return -EFAULT;
    }
    // The exact mask the C statx interposer reports: BASIC_STATS (BLOCKS the
    // allocated count stat reports) plus what `volume::statx_extra`
    // adds: the node's mount id, and STATX_BTIME when requested and the
    // node's filesystem records one.
    const STATX_BASIC_STATS: u32 = 0x07ff;
    const STATX_BTIME: u32 = 0x0800;
    let (extra, mount_id) = crate::volume::statx_extra(values.fs, flags_mask as u32);
    let timestamp = |time: crate::PatinaTimestamp| StatxTimestamp {
        tv_sec: time.sec,
        tv_nsec: time.nsec as u32,
        __reserved: 0,
    };
    let mut stx = Statx {
        stx_mask: STATX_BASIC_STATS | extra,
        stx_blksize: stat_blksize(&values) as u32,
        stx_mode: stat_mode(&values) as u16,
        stx_nlink: values.nlink,
        stx_uid: stat_owner(&values).0,
        stx_gid: stat_owner(&values).1,
        stx_ino: values.ino,
        stx_size: values.length,
        stx_blocks: values.blocks,
        stx_atime: timestamp(values.atime),
        stx_mtime: timestamp(values.mtime),
        stx_ctime: timestamp(values.ctime),
        stx_mnt_id: mount_id,
        stx_dev_major: crate::fs_device(values.fs).0,
        stx_dev_minor: crate::fs_device(values.fs).1,
        stx_rdev_major: values.rdev_major,
        stx_rdev_minor: values.rdev_minor,
        ..Statx::default()
    };
    if extra & STATX_BTIME != 0 {
        stx.stx_btime = timestamp(values.btime);
    }
    // SAFETY: `statxbuf` is the guest's `struct statx` storage.
    unsafe { (statxbuf as *mut Statx).write(stx) };
    0
}

// ---- statfs / fstatfs ----

/// `statfs(2)`: the one description the C `statfs` answers too.
pub(in crate::sud) fn sys_statfs(path: u64, buf: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a guest C string; `buf` the guest's `struct statfs`.
    ret_i32(unsafe { crate::volume::patina_statfs(path, (buf as *mut c_void).cast()) })
}

/// `fstatfs(2)`.
pub(in crate::sud) fn sys_fstatfs(fd: i64, buf: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf` is the guest's `struct statfs` storage.
    ret_i32(unsafe { crate::volume::patina_fstatfs(fd as c_int, (buf as *mut c_void).cast()) })
}
