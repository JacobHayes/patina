//! SUD rows — filesystem namespace and metadata: `openat`, `fstat`/
//! `newfstatat`/`statx`, `getdents64`, the create/unlink/link/rename/chmod/
//! access rows, and the process state behind them (`getcwd`/`chdir`/`fchdir`/
//! `umask`).
//!
//! Every path-taking row hands its `(dirfd, path)` pair to the SAME `patina_*`
//! entry the C interposer of that name calls, and that entry resolves it
//! through the one resolver (`crate::paths`): the working directory for
//! `AT_FDCWD`, a directory descriptor's NODE otherwise, `..`, symlink walking,
//! `ENAMETOOLONG`/`ENOTDIR`/`ELOOP`. There is no second resolution here — only
//! the decode from kernel flag words onto the runtime's vocabulary.
//!
//! Linux directory ITERATION (`getdents64`) is the one thing a plain filesystem
//! fd cannot answer, so this layer keeps a per-dir-fd position and entry
//! snapshot on the side, taken through `patina_read_dir`. The snapshot is taken
//! by the first `getdents64` after an open or a seek, and dropped by a seek and
//! by `close`. The C `readdir` family reads through this row into its `DIR`'s
//! buffer, as glibc's does, so a guest mixing `readdir(d)` with a raw
//! `getdents64(dirfd(d))` reads one cursor.

use super::*;

/// The directory-iteration snapshot behind a directory fd. The snapshot pointer
/// is a `Box<ReadDirState>` owned by `patina_read_dir`; it is only ever touched
/// under [`DIR_ITERATIONS`]'s lock, so passing it across threads is sound (the
/// raw pointer is stored as `usize` to keep the map `Send`).
pub(super) struct DirIteration {
    /// The live snapshot, or 0 before the first read after an open or a seek.
    snapshot: usize,
    /// How many snapshot entries the guest has been handed: the directory's
    /// position, which `lseek` reports and sets and each entry's `d_off`
    /// carries.
    position: u64,
    /// An entry read from the snapshot that did not fit the previous
    /// `getdents64` buffer, held so the next call emits it first (the kernel
    /// never drops an entry it could not return). `patina_read_dir_next` only
    /// advances, so there is no peek — this is the one-slot push-back.
    pending: Option<DirRecord>,
}

/// One listed entry: its name, `PATINA_ENTRY_*` kind and inode.
pub(super) struct DirRecord {
    name: Vec<u8>,
    kind: u32,
    ino: u64,
}

/// Live `getdents64` snapshots, keyed by the runtime directory fd. Only fds the
/// runtime's own directory table already knows ever appear here.
pub(super) static DIR_ITERATIONS: Mutex<BTreeMap<i32, DirIteration>> = Mutex::new(BTreeMap::new());

/// What `fd` names, per the descriptor table shared with the C interposers:
/// `None` for a number that names nothing (or cannot be a number at all).
pub(super) fn fd_kind(fd: i64) -> Option<c_int> {
    if fd < 0 || fd > c_int::MAX as i64 {
        return None;
    }
    // SAFETY: a plain table lookup; no pointers.
    let kind = unsafe { patina_fd_kind(fd as c_int) };
    (kind >= 0).then_some(kind)
}

/// A guest path pointer, or `EFAULT` for null. Every path row reads its path
/// through here so a null pointer is an errno, never a dereference.
pub(super) fn guest_path(path: u64) -> Result<*const c_char, i64> {
    if path == 0 {
        return Err(-EFAULT);
    }
    Ok(path as *const c_char)
}

/// The `AT_*` resolution flags a row accepts, decoded onto the runtime's
/// `PATINA_RESOLVE_*` vocabulary.
fn resolve_flags(flags: u64) -> u32 {
    let mut resolve = 0;
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        resolve |= PATINA_RESOLVE_NOFOLLOW;
    }
    if flags & AT_EMPTY_PATH != 0 {
        resolve |= PATINA_RESOLVE_EMPTY_PATH;
    }
    resolve
}

/// Does this `*at` call name the descriptor itself (`AT_EMPTY_PATH` with an
/// empty or null path)? The `fstat`-through-`newfstatat`/`statx` form every
/// modern std uses.
pub(super) fn is_empty_path(path: u64, flags: u64) -> bool {
    if flags & AT_EMPTY_PATH == 0 {
        return false;
    }
    // SAFETY: `path`, when non-null, is a guest NUL-terminated string pointer.
    path == 0 || unsafe { (path as *const u8).read() } == 0
}

/// Translate kernel `open(2)` flag bits into Patina open flags. Pure so both the
/// `openat` row and the legacy `open`/`creat` aliases (whose only difference is
/// the dirfd injection and, for `creat`, the synthesized `O_CREAT|O_WRONLY|
/// O_TRUNC`) share one decode and one source of truth. `O_PATH` and
/// `O_DIRECTORY` travel too: the one open entry decides the descriptor's kind
/// from the resolved entry's, so this layer never routes by flag.
pub(super) fn openat_patina_flags(flags: u64) -> u32 {
    let mut patina_flags = match flags & O_ACCMODE {
        O_WRONLY => PATINA_O_WRITE,
        O_RDWR => PATINA_O_READ | PATINA_O_WRITE,
        // O_RDONLY == 0
        _ => PATINA_O_READ,
    };
    if flags & O_CREAT != 0 {
        patina_flags |= PATINA_O_CREATE;
    }
    if flags & O_TRUNC != 0 {
        patina_flags |= PATINA_O_TRUNCATE;
    }
    if flags & O_APPEND != 0 {
        patina_flags |= PATINA_O_APPEND;
    }
    if flags & O_EXCL != 0 {
        patina_flags |= PATINA_O_EXCLUSIVE;
    }
    if flags & O_NOFOLLOW != 0 {
        patina_flags |= PATINA_O_NOFOLLOW;
    }
    if flags & O_NONBLOCK != 0 {
        patina_flags |= PATINA_O_NONBLOCK;
    }
    if flags & O_CLOEXEC != 0 {
        patina_flags |= PATINA_O_CLOEXEC;
    }
    if flags & O_PATH != 0 {
        // `O_PATH` opens nothing: the kernel ignores the access mode and every
        // creating flag under it, and so does the open entry.
        patina_flags = (patina_flags
            & !(PATINA_O_READ
                | PATINA_O_WRITE
                | PATINA_O_CREATE
                | PATINA_O_TRUNCATE
                | PATINA_O_APPEND
                | PATINA_O_EXCLUSIVE))
            | PATINA_O_PATH;
    }
    if flags & O_DIRECTORY != 0 {
        patina_flags |= PATINA_O_DIRECTORY;
    }
    patina_flags
}

/// The kernel `open(2)` flag bits the deterministic filesystem models. Mirrors
/// the C `patina_openat_impl`'s `supported` mask exactly: a bit outside it names
/// a behavior nothing here implements (`O_TMPFILE`, `O_DIRECT`, `O_SYNC`, …), so
/// it fails closed rather than being silently dropped.
/// (`O_NONBLOCK` changes the open of exactly one modeled kind — a FIFO, where
/// it turns the rendezvous with the opposite end into an immediate answer. On a
/// regular file or a directory it is the no-op it is on every Unix.)
pub(super) const OPENAT_SUPPORTED_FLAGS: u64 = O_ACCMODE
    | O_CREAT
    | O_TRUNC
    | O_APPEND
    | O_EXCL
    | O_CLOEXEC
    | O_LARGEFILE
    | O_NOFOLLOW
    | O_DIRECTORY
    | O_PATH
    | O_NONBLOCK;

/// Every flag `open(2)` defines (`VALID_OPEN_FLAGS`): what `openat2` accepts
/// before refusing the rest, where `openat` silently drops unknown bits.
const OPEN_VALID_FLAGS: u64 = OPENAT_SUPPORTED_FLAGS
    | uapi::O_NOCTTY as u64
    | uapi::__O_SYNC as u64
    | uapi::O_DSYNC as u64
    | uapi::FASYNC as u64
    | O_DIRECT
    | uapi::O_NOATIME as u64
    | uapi::__O_TMPFILE as u64;

/// `O_PATH_FLAGS`: what may accompany `O_PATH` in an `openat2`.
const OPEN_PATH_FLAGS: u64 = O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC;

/// `S_IALLUGO`: the mode bits a creating `openat2` may carry.
const OPEN_HOW_MODE: u64 = 0o7777;

/// `OPEN_HOW_SIZE_VER0`: `struct open_how`'s `flags`, `mode` and `resolve`.
const OPEN_HOW_SIZE: usize = size_of::<uapi::open_how>();

const RESOLVE_NO_XDEV: u64 = uapi::RESOLVE_NO_XDEV as u64;
const RESOLVE_NO_MAGICLINKS: u64 = uapi::RESOLVE_NO_MAGICLINKS as u64;
const RESOLVE_NO_SYMLINKS: u64 = uapi::RESOLVE_NO_SYMLINKS as u64;
const RESOLVE_BENEATH: u64 = uapi::RESOLVE_BENEATH as u64;
const RESOLVE_IN_ROOT: u64 = uapi::RESOLVE_IN_ROOT as u64;
const RESOLVE_CACHED: u64 = uapi::RESOLVE_CACHED as u64;

/// `openat2(2)`: `copy_struct_from_user` of the guest's `struct open_how`
/// (smaller than its first version is `EINVAL`, larger than a page `E2BIG`,
/// and any nonzero byte past the known fields `E2BIG`), then
/// `build_open_flags`' strict checks, then the one open entry with its
/// resolution restricted. A restriction with nothing to refuse here is
/// accepted as the no-op it is: the volume is memory, so every lookup
/// `RESOLVE_CACHED` allows is cached.
pub(super) fn sys_openat2(dirfd: i64, path: u64, how: u64, size: u64) -> i64 {
    let Ok(size) = usize::try_from(size) else {
        return -E2BIG;
    };
    if size < OPEN_HOW_SIZE {
        return -EINVAL;
    }
    if size > crate::PAGE_SIZE {
        return -E2BIG;
    }
    if how == 0 {
        return -EFAULT;
    }
    // SAFETY: the guest's `size`-byte `struct open_how`.
    let bytes = unsafe { core::slice::from_raw_parts(how as *const u8, size) };
    if bytes[OPEN_HOW_SIZE..].iter().any(|&byte| byte != 0) {
        return -E2BIG;
    }
    let field = |index: usize| {
        let at = index * size_of::<u64>();
        u64::from_ne_bytes(
            bytes[at..at + size_of::<u64>()]
                .try_into()
                .expect("8 bytes"),
        )
    };
    let (flags, mode, resolve) = (field(0), field(1), field(2));
    if flags & !OPEN_VALID_FLAGS != 0 {
        return -EINVAL;
    }
    if resolve
        & !(RESOLVE_NO_XDEV
            | RESOLVE_NO_MAGICLINKS
            | RESOLVE_NO_SYMLINKS
            | RESOLVE_BENEATH
            | RESOLVE_IN_ROOT
            | RESOLVE_CACHED)
        != 0
    {
        return -EINVAL;
    }
    if resolve & RESOLVE_BENEATH != 0 && resolve & RESOLVE_IN_ROOT != 0 {
        return -EINVAL;
    }
    let creating = flags & (O_CREAT | uapi::__O_TMPFILE as u64) != 0;
    if (creating && mode & !OPEN_HOW_MODE != 0) || (!creating && mode != 0) {
        return -EINVAL;
    }
    // `O_PATH` takes only the flags that shape a location; `openat` strips
    // the rest, `openat2` refuses them.
    if flags & O_PATH != 0 && flags & !OPEN_PATH_FLAGS != 0 {
        return -EINVAL;
    }
    if flags & !OPENAT_SUPPORTED_FLAGS != 0 {
        return -ENOSYS;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let mut scope = 0;
    for (bit, restriction) in [
        (RESOLVE_NO_XDEV, PATINA_RESOLVE_NO_XDEV),
        (RESOLVE_NO_SYMLINKS, PATINA_RESOLVE_NO_SYMLINKS),
        (RESOLVE_BENEATH, PATINA_RESOLVE_BENEATH),
        (RESOLVE_IN_ROOT, PATINA_RESOLVE_IN_ROOT),
        (RESOLVE_CACHED, PATINA_RESOLVE_CACHED),
        (RESOLVE_NO_MAGICLINKS, PATINA_RESOLVE_NO_MAGICLINKS),
    ] {
        if resolve & bit != 0 {
            scope |= restriction;
        }
    }
    // SAFETY: `path` is the guest's NUL-terminated string pointer.
    ret_i32(unsafe {
        patina_openat2(
            dirfd as c_int,
            path,
            openat_patina_flags(flags),
            mode as u32,
            scope,
        )
    })
}

/// `openat(2)`: one decode of the flag word, then the one open entry the C
/// interposer calls too. The creation mode is the raw syscall's fourth
/// argument; the kernel reads it only when the flags can create the entry, the
/// open entry applies the same rule (and the umask), so an open of an existing
/// file carries no mode at all.
pub(super) fn sys_openat(dirfd: i64, path: u64, flags: u64, mode: u64) -> i64 {
    if flags & !OPENAT_SUPPORTED_FLAGS != 0 {
        return -ENOSYS;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is the guest's NUL-terminated string pointer.
    ret_i32(unsafe {
        patina_openat(
            dirfd as c_int,
            path,
            openat_patina_flags(flags),
            (mode & 0o7777) as u32,
        )
    })
}

/// Drop any live `getdents64` snapshot for `fd` (a rewind through
/// `patina_seek`, and every close of the descriptor). The next `getdents64`
/// takes a fresh one from the start.
///
/// The universal `patina_close` calls this for every vacated number, so a
/// descriptor opened with a raw `openat` and iterated with a raw `getdents64`
/// but closed through *libc* still releases its snapshot — the two entry paths
/// share the descriptor, so they must share its teardown.
pub(crate) fn release_dir_iteration(fd: c_int) {
    if let Some(iteration) = DIR_ITERATIONS.lock().unwrap().remove(&fd) {
        // SAFETY: `snapshot` is null or the live `patina_read_dir` box for this fd.
        unsafe { patina_read_dir_free(iteration.snapshot as *mut c_void) };
    }
}

/// `lseek(2)` on directory descriptor `fd`, as tmpfs's `dcache_dir_lseek`
/// answers it: `SEEK_SET` and `SEEK_CUR` move the position (a negative result
/// is `EINVAL`), `SEEK_CUR 0` only reports it, and every other `whence` is
/// `EINVAL` (`None`). A move drops the snapshot, so the next `getdents64`
/// takes a fresh one and resumes that many entries in — which is what a
/// `d_off` cookie resumes from, and what `lseek(fd, 0, SEEK_SET)` (rustix
/// `Dir::rewind`) rewinds to.
pub(crate) fn seek_dir_iteration(fd: c_int, offset: i64, whence: u32) -> Option<u64> {
    let mut map = DIR_ITERATIONS.lock().unwrap();
    let position = map.get(&fd).map_or(0, |dir| dir.position);
    let target = match whence {
        uapi::SEEK_SET => offset,
        uapi::SEEK_CUR if offset == 0 => return Some(position),
        uapi::SEEK_CUR => i64::try_from(position).ok()?.checked_add(offset)?,
        _ => return None,
    };
    let target = u64::try_from(target).ok()?;
    if let Some(dir) = map.insert(
        fd,
        DirIteration {
            snapshot: 0,
            position: target,
            pending: None,
        },
    ) {
        // SAFETY: `snapshot` is null or the live `patina_read_dir` box for this fd.
        unsafe { patina_read_dir_free(dir.snapshot as *mut c_void) };
    }
    Some(target)
}

// ---- Metadata (fstat / newfstatat / statx) ----

/// The metadata record the runtime fills (`struct patina_metadata`): the same
/// one the C stat family normalizes. `mode` carries the permission bits
/// (`0o7777`) WITHOUT the file-type bits; `kind` carries those, and `st_mode`
/// is the two ORed together — see [`stat_mode`].
pub(super) type StatValues = PatinaMetadata;

const fn empty_metadata() -> PatinaMetadata {
    PatinaMetadata {
        kind: 0,
        mode: 0,
        nlink: 0,
        fs: 0,
        length: 0,
        ino: 0,
        atime: PatinaTimestamp { sec: 0, nsec: 0 },
        mtime: PatinaTimestamp { sec: 0, nsec: 0 },
        ctime: PatinaTimestamp { sec: 0, nsec: 0 },
        btime: PatinaTimestamp { sec: 0, nsec: 0 },
    }
}

/// The virtual volume's block geometry, the same 4 KiB the statfs profile
/// reports: `st_blksize`, and `st_blocks` in the 512-byte units `stat(2)`
/// counts. Byte for byte with the C `patina_stat_blocks`.
const STAT_BLOCK_SIZE: u64 = 4096;
fn stat_blocks(length: u64) -> u64 {
    length.div_ceil(STAT_BLOCK_SIZE) * (STAT_BLOCK_SIZE / 512)
}

/// The one virtual volume's mount id (`stx_mnt_id`), the C
/// `PATINA_STATX_MNT_ID`.
const STATX_MNT_ID_VALUE: u64 = crate::volume::ROOT_MOUNT.id as u64;

/// `st_mode`: the entry's file-type bits ORed with its permission bits, byte
/// for byte with the C `patina_stat_mode`.
pub(super) fn stat_mode(values: &StatValues) -> u32 {
    let kind = match values.kind {
        PATINA_ENTRY_DIRECTORY => S_IFDIR,
        PATINA_ENTRY_SYMLINK => S_IFLNK,
        PATINA_ENTRY_FIFO => S_IFIFO,
        PATINA_ENTRY_SOCKET => S_IFSOCK,
        PATINA_ENTRY_CHAR => S_IFCHR,
        _ => S_IFREG,
    };
    kind | (values.mode & 0o7777)
}

/// The owner `stat` reports, byte for byte with the C `patina_stat_uid`/
/// `patina_stat_gid`: the one modeled identity's, but for a namespace file,
/// whose nsfs inode is root's.
fn stat_owner(values: &StatValues) -> (u32, u32) {
    if values.fs == crate::PATINA_FS_NSFS {
        return (0, 0);
    }
    // SAFETY: plain constant reads.
    unsafe { (patina_uid(), patina_gid()) }
}

/// The kernel's `new_encode_dev`: the 32-bit device word `struct stat` carries.
fn encode_dev((major, minor): (u32, u32)) -> u64 {
    u64::from((minor & 0xff) | (major << 8) | ((minor & !0xff) << 12))
}

/// The kernel `struct stat` for the `fstat`/`newfstatat` syscalls. The layout is
/// arch-specific (x86_64 vs the arm64 generic layout); the fields the C
/// `fill_stat` sets are populated (the device of the node's filesystem, mode,
/// link count, inode, size, the owner from the one modeled identity, the three
/// timestamps, the block geometry); `st_rdev` stays zero.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default)]
pub(super) struct KernelStat {
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
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default)]
pub(super) struct KernelStat {
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
}

impl KernelStat {
    fn from_values(values: &StatValues) -> Self {
        Self {
            st_dev: encode_dev(crate::fs_device(values.fs)),
            st_mode: stat_mode(values),
            st_nlink: values.nlink as _,
            st_ino: values.ino,
            st_size: values.length as i64,
            st_uid: stat_owner(values).0,
            st_gid: stat_owner(values).1,
            st_blksize: STAT_BLOCK_SIZE as _,
            st_blocks: stat_blocks(values.length) as i64,
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

pub(super) fn fd_stat_values(fd: c_int) -> Result<StatValues, i64> {
    let mut v = empty_metadata();
    // SAFETY: the out-pointer is writable local storage.
    let rc = unsafe { patina_fd_metadata_full(fd, &mut v) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return Err(-(unsafe { patina_errno() } as i64));
    }
    Ok(v)
}

/// The metadata of what `(dirfd, path)` resolves to, through the one by-path
/// metadata entry the C stat family calls (`flags` are `PATINA_RESOLVE_*`).
pub(super) fn path_stat_values(dirfd: i64, path: u64, flags: u32) -> Result<StatValues, i64> {
    let path = guest_path(path)?;
    let mut v = empty_metadata();
    // SAFETY: `path` is a valid guest C string; the out-pointer is local storage.
    let rc = unsafe { patina_metadata_at(dirfd as c_int, path, flags, &mut v) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return Err(-(unsafe { patina_errno() } as i64));
    }
    Ok(v)
}

pub(super) fn write_kernel_stat(values: &StatValues, out: u64) -> i64 {
    if out == 0 {
        return -EINVAL;
    }
    // SAFETY: `out` is the guest's `struct stat` storage.
    unsafe { (out as *mut KernelStat).write(KernelStat::from_values(values)) };
    0
}

pub(super) fn sys_fstat(fd: i64, statbuf: u64) -> i64 {
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
pub(super) const STAT_AT_FLAGS: u64 =
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
pub(super) fn stat_at_values(dirfd: i64, path: u64, flags: u64) -> Result<StatValues, i64> {
    if flags & !STAT_AT_FLAGS != 0 {
        return Err(-EINVAL);
    }
    let dirfd = dirfd as c_int;
    if dirfd != AT_FDCWD as c_int && is_empty_path(path, flags) {
        return fd_stat_values(dirfd);
    }
    path_stat_values(dirfd.into(), path, resolve_flags(flags))
}

pub(super) fn sys_newfstatat(dirfd: i64, path: u64, statbuf: u64, flags: u64) -> i64 {
    match stat_at_values(dirfd, path, flags) {
        Ok(values) => write_kernel_stat(&values, statbuf),
        Err(errno) => errno,
    }
}

/// Kernel `struct statx_timestamp`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(super) struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

/// Kernel `struct statx` (arch-independent).
#[repr(C)]
#[derive(Default)]
pub(super) struct Statx {
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

pub(super) fn sys_statx(dirfd: i64, path: u64, flags: u64, flags_mask: u64, statxbuf: u64) -> i64 {
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
    // length-derived count stat reports) plus what `volume::statx_extra`
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
        stx_blksize: STAT_BLOCK_SIZE as u32,
        stx_mode: stat_mode(&values) as u16,
        stx_nlink: values.nlink,
        stx_uid: stat_owner(&values).0,
        stx_gid: stat_owner(&values).1,
        stx_ino: values.ino,
        stx_size: values.length,
        stx_blocks: stat_blocks(values.length),
        stx_atime: timestamp(values.atime),
        stx_mtime: timestamp(values.mtime),
        stx_ctime: timestamp(values.ctime),
        stx_mnt_id: mount_id,
        stx_dev_major: crate::fs_device(values.fs).0,
        stx_dev_minor: crate::fs_device(values.fs).1,
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
pub(super) fn sys_statfs(path: u64, buf: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a guest C string; `buf` the guest's `struct statfs`.
    ret_i32(unsafe { patina_statfs(path, buf as *mut c_void) })
}

/// `fstatfs(2)`.
pub(super) fn sys_fstatfs(fd: i64, buf: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf` is the guest's `struct statfs` storage.
    ret_i32(unsafe { patina_fstatfs(fd as c_int, buf as *mut c_void) })
}

// ---- extended attributes ----

/// Which node a path row names: the path, its final symlink followed or
/// not (the `l*` rows).
fn xattr_by(follow: bool) -> c_int {
    if follow {
        crate::xattr::XATTR_BY_PATH
    } else {
        crate::xattr::XATTR_BY_LINK
    }
}

pub(super) fn sys_getxattr(path: u64, name: u64, value: u64, size: u64, follow: bool) -> i64 {
    // SAFETY: guest pointers per the getxattr(2) contract.
    ret_isize(unsafe {
        patina_getxattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            name as *const c_char,
            value as *mut c_void,
            size as usize,
        )
    })
}

pub(super) fn sys_fgetxattr(fd: i64, name: u64, value: u64, size: u64) -> i64 {
    // SAFETY: guest pointers per the fgetxattr(2) contract.
    ret_isize(unsafe {
        patina_getxattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            name as *const c_char,
            value as *mut c_void,
            size as usize,
        )
    })
}

pub(super) fn sys_listxattr(path: u64, list: u64, size: u64, follow: bool) -> i64 {
    // SAFETY: guest pointers per the listxattr(2) contract.
    ret_isize(unsafe {
        patina_listxattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            list as *mut c_void,
            size as usize,
        )
    })
}

pub(super) fn sys_flistxattr(fd: i64, list: u64, size: u64) -> i64 {
    // SAFETY: guest pointers per the flistxattr(2) contract.
    ret_isize(unsafe {
        patina_listxattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            list as *mut c_void,
            size as usize,
        )
    })
}

pub(super) fn sys_setxattr(
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
    follow: bool,
) -> i64 {
    // SAFETY: guest pointers per the setxattr(2) contract.
    ret_i32(unsafe {
        patina_setxattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            name as *const c_char,
            value as *const c_void,
            size as usize,
            flags as c_int,
        )
    })
}

pub(super) fn sys_fsetxattr(fd: i64, name: u64, value: u64, size: u64, flags: u64) -> i64 {
    // SAFETY: guest pointers per the fsetxattr(2) contract.
    ret_i32(unsafe {
        patina_setxattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            name as *const c_char,
            value as *const c_void,
            size as usize,
            flags as c_int,
        )
    })
}

pub(super) fn sys_removexattr(path: u64, name: u64, follow: bool) -> i64 {
    // SAFETY: guest pointers per the removexattr(2) contract.
    ret_i32(unsafe {
        patina_removexattr(
            -1,
            path as *const c_char,
            xattr_by(follow),
            name as *const c_char,
        )
    })
}

pub(super) fn sys_fremovexattr(fd: i64, name: u64) -> i64 {
    // SAFETY: guest pointers per the fremovexattr(2) contract.
    ret_i32(unsafe {
        patina_removexattr(
            fd as c_int,
            std::ptr::null(),
            crate::xattr::XATTR_BY_FD,
            name as *const c_char,
        )
    })
}

// ---- name_to_handle_at ----

/// `name_to_handle_at`'s flags: `AT_SYMLINK_FOLLOW`, `AT_EMPTY_PATH`, and
/// `AT_HANDLE_FID` (Linux 6.5; the value `AT_REMOVEDIR` has).
const AT_HANDLE_FID: u64 = AT_REMOVEDIR;
const NAME_TO_HANDLE_FLAGS: u64 = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID;

/// `MAX_HANDLE_SZ`: the largest handle a caller may declare room for.
const MAX_HANDLE_SZ: u32 = 128;

/// ext4's handle shape (`FILEID_INO32_GEN`): the inode number and its
/// generation, two 32-bit words; `FILEID_INVALID` when the caller's room is
/// short.
const FILEID_INO32_GEN: i32 = 1;
const FILEID_INVALID: i32 = 255;
const HANDLE_BYTES: u32 = 8;

/// The volume's mount id, the one `statx` reports.
const MOUNT_ID: i32 = STATX_MNT_ID_VALUE as i32;

/// The fixed header of a guest `struct file_handle`.
#[repr(C)]
struct FileHandleHeader {
    handle_bytes: u32,
    handle_type: i32,
}

/// `name_to_handle_at(2)` (`fs/fhandle.c`): the flags first (`EINVAL`), then
/// the path (`AT_SYMLINK_FOLLOW` follows a final symlink, `AT_EMPTY_PATH`
/// names the descriptor), then whether the node's filesystem can encode one
/// at all (`EOPNOTSUPP` on a pseudo-filesystem, before the handle is read),
/// then the caller's declared room (`EINVAL` past `MAX_HANDLE_SZ`). A handle
/// names the node: the inode number and a zero generation, as ext4 encodes
/// one; room for less than that is `EOVERFLOW` with the size it needs written
/// back. The mount id is the volume's.
pub(super) fn sys_name_to_handle_at(
    dirfd: i64,
    path: u64,
    handle: u64,
    mount_id: u64,
    flags: u64,
) -> i64 {
    if flags & !NAME_TO_HANDLE_FLAGS != 0 {
        return -EINVAL;
    }
    let resolve = if flags & AT_SYMLINK_FOLLOW != 0 {
        0
    } else {
        PATINA_RESOLVE_NOFOLLOW
    } | if flags & AT_EMPTY_PATH != 0 {
        PATINA_RESOLVE_EMPTY_PATH
    } else {
        0
    };
    let values = if dirfd as c_int != AT_FDCWD as c_int && is_empty_path(path, flags) {
        fd_stat_values(dirfd as c_int)
    } else {
        path_stat_values(dirfd, path, resolve)
    };
    let values = match values {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    // A filesystem with no export operations refuses before the handle is
    // read (`exportfs_can_encode_fh`).
    if values.fs != crate::PATINA_FS_VOLUME {
        return -EOPNOTSUPP;
    }
    if handle == 0 {
        return -EFAULT;
    }
    let header = handle as *mut FileHandleHeader;
    // SAFETY: `handle` is the guest's `struct file_handle`.
    let room = unsafe { header.read_unaligned() }.handle_bytes;
    if room > MAX_HANDLE_SZ {
        return -EINVAL;
    }
    let fits = room >= HANDLE_BYTES;
    // SAFETY: the header is the guest's; the payload follows it and has
    // `room >= HANDLE_BYTES` bytes when written.
    unsafe {
        header.write_unaligned(FileHandleHeader {
            handle_bytes: HANDLE_BYTES,
            handle_type: if fits {
                FILEID_INO32_GEN
            } else {
                FILEID_INVALID
            },
        });
        if fits {
            let payload = (handle as *mut u8).add(std::mem::size_of::<FileHandleHeader>());
            let mut words = [0u8; HANDLE_BYTES as usize];
            words[..4].copy_from_slice(&(values.ino as u32).to_ne_bytes());
            std::ptr::copy_nonoverlapping(words.as_ptr(), payload, words.len());
        }
    }
    if mount_id == 0 {
        return -EFAULT;
    }
    // SAFETY: `mount_id` is the guest's `int`.
    unsafe { (mount_id as *mut i32).write_unaligned(MOUNT_ID) };
    if fits { 0 } else { -EOVERFLOW }
}

// ---- getdents64 ----

pub(super) fn dt_for_kind(kind: u32) -> u8 {
    match kind {
        PATINA_ENTRY_DIRECTORY => DT_DIR,
        PATINA_ENTRY_SYMLINK => DT_LNK,
        PATINA_ENTRY_FIFO => DT_FIFO,
        PATINA_ENTRY_SOCKET => DT_SOCK,
        PATINA_ENTRY_CHAR => DT_CHR,
        _ => DT_REG,
    }
}

/// The directory-record layout a `getdents` row fills.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DirentFormat {
    /// `struct linux_dirent64` (`getdents64`): `d_ino`, `d_off`, `d_reclen`,
    /// `d_type`, then the name.
    Dirent64,
    /// The legacy `struct linux_dirent` (x86_64 `getdents`): `d_ino`, `d_off`,
    /// `d_reclen`, the name, and the type in the record's LAST byte, after the
    /// name's padding (`fs/readdir.c filldir`).
    #[cfg(target_arch = "x86_64")]
    Dirent,
}

impl DirentFormat {
    /// The fixed header before the name: `d_ino` and `d_off` (8 bytes each on
    /// a 64-bit kernel), `d_reclen`, and for `linux_dirent64` `d_type`.
    fn header(self) -> usize {
        match self {
            DirentFormat::Dirent64 => 19,
            #[cfg(target_arch = "x86_64")]
            DirentFormat::Dirent => 18,
        }
    }

    /// A record's length: header, name, its NUL (and, for the legacy layout,
    /// the type byte), 8-byte aligned.
    fn reclen(self, name_len: usize) -> usize {
        let trailer = match self {
            DirentFormat::Dirent64 => 1,
            #[cfg(target_arch = "x86_64")]
            DirentFormat::Dirent => 2,
        };
        (self.header() + name_len + trailer + 7) & !7
    }
}

/// Fill the guest buffer with directory records from the fd's snapshot,
/// advancing `patina_read_dir_next` past every entry that fits. Returns the
/// number of bytes written (0 at end-of-directory) or `-errno`.
pub(super) fn sys_getdents64(fd: i64, dirp: u64, count: u64) -> i64 {
    getdents(fd, dirp, count, DirentFormat::Dirent64)
}

pub(super) fn getdents(fd: i64, dirp: u64, count: u64, format: DirentFormat) -> i64 {
    // Linux directory iteration needs an opened directory (`fdget_pos`): a
    // number that names nothing, or an `O_PATH` one, is EBADF; anything else
    // (a file, a socket) is ENOTDIR.
    match c_int::try_from(fd).map(crate::fdget) {
        Err(_) | Ok(Err(_)) => return -EBADF,
        Ok(Ok(resolved)) if resolved.kind == crate::fdtable::FdKind::Dir => {}
        Ok(Ok(_)) => return -ENOTDIR,
    }
    if dirp == 0 {
        return -EFAULT;
    }
    // The kernel reads the length as an unsigned int.
    let cap = count as u32 as usize;
    // The snapshot is taken by the FIRST getdents on the descriptor (and after
    // a seek), through the same `patina_read_dir` entry the interposed
    // `opendir` uses — a second caller, never a second directory model.
    let Ok(fd) = c_int::try_from(fd) else {
        return -EBADF;
    };
    let mut map = DIR_ITERATIONS.lock().unwrap();
    let dir = map.entry(fd).or_insert(DirIteration {
        snapshot: 0,
        position: 0,
        pending: None,
    });
    if dir.snapshot == 0 {
        let mut snapshot: *mut c_void = std::ptr::null_mut();
        // The snapshot is read through the DESCRIPTOR: its `r` was charged at
        // open, so a later `chmod` cannot break a walk under way and an `O_PATH`
        // descriptor (which opened nothing) cannot iterate at all.
        // SAFETY: `snapshot` is writable local storage.
        let rc = unsafe { patina_read_dir(fd, &mut snapshot) };
        if rc != 0 {
            // SAFETY: plain thread-local read.
            return -(unsafe { patina_errno() } as i64);
        }
        dir.snapshot = snapshot as usize;
        // Resume at the position: skip the entries before it.
        let mut name = [0u8; 256];
        let mut kind: u32 = 0;
        let mut ino: u64 = 0;
        for _ in 0..dir.position {
            // SAFETY: `snapshot` is the live box; `name` is writable for its length.
            let rc = unsafe {
                patina_read_dir_next(
                    snapshot,
                    name.as_mut_ptr() as *mut c_char,
                    name.len(),
                    &mut kind,
                    &mut ino,
                )
            };
            if rc != 1 {
                break;
            }
        }
    }
    let snapshot = dir.snapshot as *mut c_void;
    let mut written = 0usize;
    loop {
        // Next entry: the pushed-back one first, else consume from the snapshot.
        // `patina_read_dir_next` only advances (no peek), so an entry that does
        // not fit is stashed in `dir.pending` and never dropped.
        let record = if let Some(entry) = dir.pending.take() {
            entry
        } else {
            let mut buf = [0u8; 256];
            let (mut kind, mut ino) = (0u32, 0u64);
            // SAFETY: `snapshot` is the live box; `buf` is writable for its length.
            let rc = unsafe {
                patina_read_dir_next(
                    snapshot,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                    &mut kind,
                    &mut ino,
                )
            };
            match rc {
                1 => {
                    // SAFETY: `buf` now holds a NUL-terminated name.
                    let len = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) }
                        .to_bytes()
                        .len();
                    DirRecord {
                        name: buf[..len].to_vec(),
                        kind,
                        ino,
                    }
                }
                0 => break, // end of directory
                _ => {
                    if written > 0 {
                        break;
                    }
                    // SAFETY: plain thread-local read.
                    return -(unsafe { patina_errno() } as i64);
                }
            }
        };
        let reclen = format.reclen(record.name.len());
        if written + reclen > cap {
            // No room: push the entry back for the next call and stop. If nothing
            // fit at all, the caller's buffer is too small for even one entry.
            let empty = written == 0;
            dir.pending = Some(record);
            if empty {
                return -EINVAL;
            }
            break;
        }
        // Commit: write the record into the guest buffer, zeroed first so the
        // padding carries nothing.
        // SAFETY: `dirp+written` has `reclen` bytes of room (checked above).
        unsafe {
            let rec = (dirp as *mut u8).add(written);
            std::ptr::write_bytes(rec, 0, reclen);
            (rec as *mut u64).write_unaligned(record.ino); // d_ino
            // d_off: the position after this entry, which `lseek` resumes from.
            (rec.add(8) as *mut i64).write_unaligned((dir.position + 1) as i64);
            (rec.add(16) as *mut u16).write_unaligned(reclen as u16); // d_reclen
            // d_type: after d_reclen in `linux_dirent64`, the record's last
            // byte in the legacy layout.
            let type_offset = match format {
                DirentFormat::Dirent64 => 18,
                #[cfg(target_arch = "x86_64")]
                DirentFormat::Dirent => reclen - 1,
            };
            rec.add(type_offset).write(dt_for_kind(record.kind));
            let dst = rec.add(format.header());
            std::ptr::copy_nonoverlapping(record.name.as_ptr(), dst, record.name.len());
        }
        written += reclen;
        dir.position += 1;
    }
    written as i64
}

// ---- Directory namespace ops ----

pub(super) fn sys_mkdirat(dirfd: i64, path: u64, mode: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { patina_mkdir(dirfd as c_int, path, (mode & 0o7777) as u32) })
}

/// `mknodat(2)`, the only door a raw-syscall guest has to a FIFO, a socket
/// node or a whiteout (glibc's `mkfifo`/`mkfifoat` are library wrappers over
/// this number, and rustix lowers its own onto it): the one entry the C
/// `mknod` calls too. The kernel reads the device as an `unsigned int`.
pub(super) fn sys_mknodat(dirfd: i64, path: u64, mode: u64, device: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { patina_mknod(dirfd as c_int, path, mode as u32, device as u32) })
}

pub(super) fn sys_unlinkat(dirfd: i64, path: u64, flags: u64) -> i64 {
    // AT_REMOVEDIR selects rmdir; no flag selects unlink; unknown flags fail.
    if flags & !AT_REMOVEDIR != 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    if flags & AT_REMOVEDIR != 0 {
        ret_i32(unsafe { patina_rmdir(dirfd as c_int, path) })
    } else {
        ret_i32(unsafe { patina_unlink(dirfd as c_int, path) })
    }
}

/// `symlinkat(target, newdirfd, linkpath)`. Only the LINK path is dirfd-relative
/// — `target` is the link's literal contents and is never resolved here.
pub(super) fn sys_symlinkat(target: u64, newdirfd: i64, linkpath: u64) -> i64 {
    let (target, linkpath) = match (guest_path(target), guest_path(linkpath)) {
        (Ok(target), Ok(linkpath)) => (target, linkpath),
        (Err(errno), _) | (_, Err(errno)) => return errno,
    };
    // SAFETY: both are valid NUL-terminated string pointers.
    ret_i32(unsafe { patina_symlink(target, newdirfd as c_int, linkpath) })
}

/// Existence / permission probe (`faccessat`, `faccessat2`, and the x86_64
/// legacy `access`). The guest is one non-root identity owning every modeled
/// entry, so the answer reads the OWNER triad of the entry's modeled
/// permission bits — `X_OK` included: the bit is a mode fact the kernel
/// answers from, and whether anything can actually execute is the process
/// family's business. Mirrors the C `faccessat`/`patina_access_impl` exactly,
/// including its accepted flag set: `AT_EACCESS` only chooses effective vs real
/// ids, which are one identity here.
///
/// `cap-primitives` calls this on every `..` component
/// (`accessat(base, ".", X_OK, AT_EACCESS)`), so without it a capability-style
/// guest cannot walk out of a subdirectory at all.
pub(super) fn sys_faccessat(dirfd: i64, path: u64, mode: u64, flags: u64) -> i64 {
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW) != 0 {
        return -EINVAL;
    }
    let values = match path_stat_values(dirfd, path, 0) {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    // The guest is one non-root identity owning every entry, so the OWNER triad
    // is the answer — the same arithmetic the C `patina_access_impl` does.
    let owner = (values.mode >> 6) & 0o7;
    let mut wanted = 0;
    if mode & R_OK != 0 {
        wanted |= 0o4;
    }
    if mode & W_OK != 0 {
        wanted |= 0o2;
    }
    if mode & X_OK != 0 {
        wanted |= 0o1;
    }
    if owner & wanted != wanted {
        return -EACCES;
    }
    0
}

/// Raw `fchmodat`/`fchmodat2`, and the x86_64 legacy `chmod`. Routes to the
/// same `patina_chmod` the C interposers call, so one mode model answers both
/// doors.
///
/// The kernel's `fchmodat` takes no flag argument at all — glibc's four-argument
/// wrapper emulates `AT_SYMLINK_NOFOLLOW` above it — so the flags here are
/// always `fchmodat2`'s (`do_fchmodat`): `AT_SYMLINK_NOFOLLOW` and
/// `AT_EMPTY_PATH` (an empty path names the descriptor, `O_PATH` included);
/// anything else is `EINVAL` before the path is looked at.
pub(super) fn sys_fchmodat(dirfd: i64, path: u64, mode: u64, flags: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { patina_chmod(dirfd as c_int, path, mode as u32, resolve_flags(flags)) })
}

/// Raw `fchmod` -> `patina_fchmod`. A descriptor already names the node, so
/// there is no symlink to resolve.
pub(super) fn sys_fchmod(fd: i64, mode: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: a plain runtime call with no pointers.
    ret_i32(unsafe { patina_fchmod(fd as c_int, mode as u32) })
}

/// Raw `linkat`/`link` -> the same deterministic hard link the `patina_link`
/// interposer creates (std::fs::hard_link lowers to
/// `linkat(AT_FDCWD, .., AT_FDCWD, .., 0)`). AT_SYMLINK_FOLLOW is the sole
/// defined flag: when set, `oldpath`'s trailing symlink is resolved before
/// linking, so a raw caller sees the identical follow/no-follow behavior as the
/// C `linkat` interposer; any other flag bit is EINVAL rather than silently
/// ignored.
pub(super) fn sys_linkat(
    olddirfd: i64,
    oldpath: u64,
    newdirfd: i64,
    newpath: u64,
    flags: u64,
) -> i64 {
    if flags & !AT_SYMLINK_FOLLOW != 0 {
        return -EINVAL;
    }
    let (oldpath, newpath) = match (guest_path(oldpath), guest_path(newpath)) {
        (Ok(oldpath), Ok(newpath)) => (oldpath, newpath),
        (Err(errno), _) | (_, Err(errno)) => return errno,
    };
    // SAFETY: both are valid NUL-terminated string pointers.
    ret_i32(unsafe {
        patina_link(
            olddirfd as c_int,
            oldpath,
            newdirfd as c_int,
            newpath,
            c_int::from(flags & AT_SYMLINK_FOLLOW != 0),
        )
    })
}

/// `readlinkat(2)`. An empty path names the descriptor itself (the `O_PATH`
/// trick `cap-primitives` uses to test whether a component it just opened is a
/// symlink), and since no deterministic descriptor names a symlink entry the
/// answer is the kernel's own for a non-symlink: `EINVAL`. `bufsiz <= 0` is
/// `EINVAL` before anything is resolved.
pub(super) fn sys_readlinkat(dirfd: i64, path: u64, buf: u64, bufsize: u64) -> i64 {
    if (bufsize as i64) <= 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is valid; `buf` is writable for `bufsize`.
    ret_isize(unsafe {
        patina_read_link(dirfd as c_int, path, buf as *mut c_char, bufsize as usize)
    })
}

pub(super) fn sys_renameat(
    olddirfd: i64,
    oldpath: u64,
    newdirfd: i64,
    newpath: u64,
    flags: u64,
) -> i64 {
    let (oldpath, newpath) = match (guest_path(oldpath), guest_path(newpath)) {
        (Ok(oldpath), Ok(newpath)) => (oldpath, newpath),
        (Err(errno), _) | (_, Err(errno)) => return errno,
    };
    // The kernel reads the flags as an `unsigned int`; the one rename entry
    // judges them (`crate::patina_renameat2`).
    // SAFETY: both are valid NUL-terminated string pointers.
    ret_i32(unsafe {
        patina_renameat2(
            olddirfd as c_int,
            oldpath,
            newdirfd as c_int,
            newpath,
            flags as u32,
        )
    })
}

// ---- The working directory and the umask ----

/// `getcwd(2)`: kernel semantics, not glibc's. The directory's current name is
/// copied NUL-terminated into `buf` and the byte count INCLUDING the terminator
/// is returned; a buffer too small (including `size == 0`) is `ERANGE`, and an
/// unlinked working directory is `ENOENT`.
pub(super) fn sys_getcwd(buf: u64, size: u64) -> i64 {
    if buf == 0 {
        return -EFAULT;
    }
    if size == 0 {
        return -ERANGE;
    }
    // SAFETY: `buf` is the guest's buffer, writable for `size` bytes.
    let length = unsafe { patina_getcwd(buf as *mut c_char, size as usize) };
    if length < 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    length as i64 + 1
}

/// `chdir(2)` -> the same working-directory state the C interposer sets.
pub(super) fn sys_chdir(path: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { patina_chdir(AT_FDCWD as c_int, path) })
}

/// `fchdir(2)`.
pub(super) fn sys_fchdir(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: a plain runtime call with no pointers.
    ret_i32(unsafe { patina_fchdir(fd as c_int) })
}

/// `umask(2)`: never fails; answers the previous mask.
pub(super) fn sys_umask(mask: u64) -> i64 {
    // SAFETY: a plain runtime call with no pointers.
    i64::from(unsafe { patina_umask(mask as u32) })
}

// ---- Timestamps, ownership and sizes ----

/// A kernel `struct __kernel_timespec` / `struct timespec` (x86_64: two i64).
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// A time argument on the runtime's `PATINA_TIME_*` vocabulary.
pub(super) type TimeArgument = (u32, PatinaTimestamp);

/// One `utimensat` time argument decoded as the kernel decodes it:
/// `UTIME_NOW`/`UTIME_OMIT` in `tv_nsec`, else nanoseconds that must be in
/// range (`EINVAL`) beside any second (the entry truncates it to the
/// filesystem's range).
fn time_argument(time: &KernelTimespec) -> Result<TimeArgument, i64> {
    match time.tv_nsec {
        UTIME_NOW => Ok((crate::TIME_NOW, PatinaTimestamp::default())),
        UTIME_OMIT => Ok((crate::TIME_OMIT, PatinaTimestamp::default())),
        nsec if !(0..NANOS_PER_SEC as i64).contains(&nsec) => Err(-EINVAL),
        nsec => Ok((
            crate::TIME_SET,
            PatinaTimestamp {
                sec: time.tv_sec,
                nsec,
            },
        )),
    }
}

/// The two time arguments of a `utimensat`/`utimes`-shaped row: a null
/// pointer is now/now.
pub(super) fn times_arguments<T: Copy>(
    times: u64,
    decode: impl Fn(&T) -> Result<TimeArgument, i64>,
) -> Result<[TimeArgument; 2], i64> {
    if times == 0 {
        let now = (crate::TIME_NOW, PatinaTimestamp::default());
        return Ok([now, now]);
    }
    // SAFETY: `times` is the guest's two-element array.
    let pair = unsafe { (times as *const [T; 2]).read_unaligned() };
    Ok([decode(&pair[0])?, decode(&pair[1])?])
}

/// `utimensat(2)`: NOFOLLOW and EMPTY_PATH are supported; OMIT/OMIT skips flags.
/// a null path names the descriptor itself (the `futimens` shape), which the
/// kernel accepts only flagless and not on `AT_FDCWD`.
pub(super) fn sys_utimensat(dirfd: i64, path: u64, times: u64, flags: u64) -> i64 {
    let [atime, mtime] = match times_arguments(times, time_argument) {
        Ok(times) => times,
        Err(errno) => return errno,
    };
    if atime.0 == crate::TIME_OMIT && mtime.0 == crate::TIME_OMIT {
        crate::abort_if_init_failed();
        return 0;
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    if path == 0 {
        if flags != 0 {
            return -EINVAL;
        }
        if dirfd == AT_FDCWD {
            return -EFAULT;
        }
        if let Some(err) = fd_out_of_range(dirfd) {
            return err;
        }
        // SAFETY: no pointers.
        return ret_i32(unsafe {
            patina_futimens(dirfd as c_int, atime.0, atime.1, mtime.0, mtime.1)
        });
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe {
        patina_utimensat(
            dirfd as c_int,
            path,
            resolve_flags(flags),
            atime.0,
            atime.1,
            mtime.0,
            mtime.1,
        )
    })
}

/// `fchownat(2)`, and the x86_64 legacy `chown`/`lchown`: `AT_SYMLINK_NOFOLLOW`
/// and `AT_EMPTY_PATH` are the flags (`EINVAL` otherwise). The ids are the
/// kernel's `uid_t`/`gid_t` (`-1` = unchanged), passed through as the 32-bit
/// values they are.
pub(super) fn sys_fchownat(dirfd: i64, path: u64, uid: u64, gid: u64, flags: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe {
        patina_chown(
            dirfd as c_int,
            path,
            resolve_flags(flags),
            uid as u32,
            gid as u32,
        )
    })
}

/// `fchown(2)`.
pub(super) fn sys_fchown(fd: i64, uid: u64, gid: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_fchown(fd as c_int, uid as u32, gid as u32) })
}

/// `truncate(2)`: by name, following a trailing symlink.
pub(super) fn sys_truncate(path: u64, length: i64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { patina_truncate(AT_FDCWD as c_int, path, length) })
}

/// `fallocate(2)`: the mode word is the kernel's; the one entry decodes it.
pub(super) fn sys_fallocate(fd: i64, mode: u64, offset: i64, length: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_fallocate(fd as c_int, mode as u32, offset, length) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `openat2(AT_FDCWD, path, how, size)` for a `how` of `fields` followed by
    /// zeroes out to a page, with a path past `PATH_MAX`: every answer here is
    /// decided before the path is resolved, and one that is not is
    /// `ENAMETOOLONG`, so no runtime is needed.
    fn openat2(fields: [u64; 4], size: usize) -> i64 {
        let mut how = vec![0u64; crate::PAGE_SIZE / 8 + 1];
        how[..4].copy_from_slice(&fields);
        let path = std::ffi::CString::new("a".repeat(crate::paths::PATH_MAX)).unwrap();
        sys_openat2(
            AT_FDCWD,
            path.as_ptr() as u64,
            how.as_ptr() as u64,
            size as u64,
        )
    }

    #[test]
    fn open_how_is_copied_as_copy_struct_from_user_copies_it() {
        assert_eq!(openat2([0; 4], OPEN_HOW_SIZE - 1), -EINVAL);
        assert_eq!(openat2([0; 4], crate::PAGE_SIZE + 1), -E2BIG);
        assert_eq!(openat2([0, 0, 0, 1], OPEN_HOW_SIZE + 8), -E2BIG);
        let resolved = -(errno::ENAMETOOLONG as i64);
        assert_eq!(openat2([0; 4], OPEN_HOW_SIZE + 8), resolved);
        assert_eq!(
            sys_openat2(AT_FDCWD, c"/".as_ptr() as u64, 0, OPEN_HOW_SIZE as u64),
            -EFAULT
        );
    }

    #[test]
    fn open_how_is_judged_as_build_open_flags_judges_it() {
        assert_eq!(openat2([1 << 40, 0, 0, 0], OPEN_HOW_SIZE), -EINVAL);
        assert_eq!(openat2([0, 0o644, 0, 0], OPEN_HOW_SIZE), -EINVAL);
        assert_eq!(openat2([O_CREAT, 0o10644, 0, 0], OPEN_HOW_SIZE), -EINVAL);
        assert_eq!(
            openat2([O_CREAT | O_DIRECTORY, 0o644, 0, 0], OPEN_HOW_SIZE),
            -EINVAL
        );
        assert_eq!(openat2([0, 0, 0x80, 0], OPEN_HOW_SIZE), -EINVAL);
        assert_eq!(
            openat2([0, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT, 0], OPEN_HOW_SIZE),
            -EINVAL
        );
        assert_eq!(
            openat2([O_PATH | O_WRONLY, 0, 0, 0], OPEN_HOW_SIZE),
            -EINVAL
        );
        assert_eq!(
            openat2([O_PATH | O_TRUNC, 0, RESOLVE_CACHED, 0], OPEN_HOW_SIZE),
            -EINVAL
        );
        assert_eq!(
            openat2([O_CREAT, 0o644, RESOLVE_CACHED, 0], OPEN_HOW_SIZE),
            -(errno::EAGAIN as i64)
        );
        assert_eq!(
            openat2([O_TRUNC, 0, RESOLVE_CACHED, 0], OPEN_HOW_SIZE),
            -(errno::EAGAIN as i64)
        );
        assert_eq!(
            openat2([uapi::O_NOATIME as u64, 0, 0, 0], OPEN_HOW_SIZE),
            -ENOSYS
        );
    }
}
