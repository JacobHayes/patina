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
//! fd cannot answer, so this layer keeps a per-dir-fd entry snapshot on the side,
//! taken through the SAME `patina_read_dir` entry the interposed `opendir` uses.
//! The snapshot is created by the first `getdents64` on the fd, dropped by
//! `lseek(…, 0, SEEK_SET)` (rustix `Dir::rewind`) and by `close`.

use super::*;

/// The directory-iteration snapshot behind a directory fd. The snapshot pointer
/// is a `Box<ReadDirState>` owned by `patina_read_dir`; it is only ever touched
/// under [`DIR_ITERATIONS`]'s lock, so passing it across threads is sound (the
/// raw pointer is stored as `usize` to keep the map `Send`).
pub(super) struct DirIteration {
    snapshot: usize,
    /// An entry read from the snapshot that did not fit the previous
    /// `getdents64` buffer, held so the next call emits it first (the kernel
    /// never drops an entry it could not return). `patina_read_dir_next` only
    /// advances, so there is no peek — this is the one-slot push-back.
    pending: Option<(Vec<u8>, u32)>,
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

/// Is `fd` a directory descriptor the deterministic filesystem issued? The
/// descriptor table is the single source of truth, shared with the C
/// interposers.
pub(super) fn is_dir_fd(fd: i64) -> bool {
    fd_kind(fd) == Some(PATINA_FD_DIR)
}

/// A guest path pointer, or `EFAULT` for null. Every path row reads its path
/// through here so a null pointer is an errno, never a dereference.
fn guest_path(path: u64) -> Result<*const c_char, i64> {
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

/// The deny a `mknodat` of anything but a FIFO gets. Byte-identical to the C
/// `PATINA_DENY_MKNOD_TYPE`, so a raw-syscall guest and a libc guest record the
/// same captured stderr for the same refusal.
pub(super) const DENY_MKNOD_TYPE: &str = "patina: mknod models only S_IFIFO (a named pipe); no other special file has a \
     deterministic representation here; failing closed\n";

/// The deny `openat2` gets. It has no C counterpart (glibc exports no `openat2`
/// wrapper, so no interposer can be reached), which is exactly why the raw row
/// must name it: otherwise the only signal would be an unexplained `ENOSYS`.
pub(super) const DENY_OPENAT2: &str = "patina: openat2 is not modeled (its RESOLVE_* resolution guarantees are a kernel-side \
     sandbox the deterministic filesystem does not implement); failing closed so callers take \
     their component-wise openat fallback\n";

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

/// Drop any live `getdents64` snapshot for `fd` (rustix `Dir::rewind`, and every
/// close of the descriptor). The next `getdents64` takes a fresh one from the
/// start.
///
/// The universal `patina_close` calls this for every vacated number, so a
/// descriptor opened with a raw `openat` and iterated with a raw `getdents64`
/// but closed through *libc* still releases its snapshot — the two entry paths
/// share the descriptor, so they must share its teardown.
pub(crate) fn release_dir_iteration(fd: c_int) {
    if let Some(iteration) = DIR_ITERATIONS.lock().unwrap().remove(&fd) {
        // SAFETY: `snapshot` is the live `patina_read_dir` box for this fd.
        unsafe { patina_read_dir_free(iteration.snapshot as *mut c_void) };
    }
}

// ---- Metadata (fstat / newfstatat / statx) ----

pub(super) struct StatValues {
    kind: u32,
    length: u64,
    ino: u64,
    nlink: u32,
    atime_nanos: u64,
    mtime_nanos: u64,
    /// Permission bits (`0o7777`) WITHOUT the file-type bits; `kind` carries
    /// those. `st_mode` is the two ORed together — see [`stat_mode`].
    mode: u32,
}

impl StatValues {
    const fn empty() -> Self {
        Self {
            kind: 0,
            length: 0,
            ino: 0,
            nlink: 0,
            atime_nanos: 0,
            mtime_nanos: 0,
            mode: 0,
        }
    }
}

/// `st_mode`: the entry's file-type bits ORed with its permission bits, byte
/// for byte with the C `patina_stat_mode`.
pub(super) fn stat_mode(values: &StatValues) -> u32 {
    let kind = match values.kind {
        PATINA_ENTRY_DIRECTORY => S_IFDIR,
        PATINA_ENTRY_SYMLINK => S_IFLNK,
        PATINA_ENTRY_FIFO => S_IFIFO,
        _ => S_IFREG,
    };
    kind | (values.mode & 0o7777)
}

/// The kernel `struct stat` for the `fstat`/`newfstatat` syscalls. The layout is
/// arch-specific (x86_64 vs the arm64 generic layout); only the fields the C
/// `fill_stat` sets are populated, the rest stay zero.
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
        let mut stat = Self::default();
        stat.st_mode = stat_mode(values);
        stat.st_nlink = values.nlink as _;
        stat.st_ino = values.ino;
        stat.st_size = values.length as i64;
        stat.st_atime = (values.atime_nanos / NANOS_PER_SEC) as i64;
        stat.st_atime_nsec = (values.atime_nanos % NANOS_PER_SEC) as _;
        stat.st_mtime = (values.mtime_nanos / NANOS_PER_SEC) as i64;
        stat.st_mtime_nsec = (values.mtime_nanos % NANOS_PER_SEC) as _;
        stat.st_ctime = stat.st_mtime;
        stat.st_ctime_nsec = stat.st_mtime_nsec;
        stat
    }
}

pub(super) fn fd_stat_values(fd: c_int) -> Result<StatValues, i64> {
    let mut v = StatValues::empty();
    // SAFETY: all out-pointers are writable local storage.
    let rc = unsafe {
        patina_fd_metadata_full(
            fd,
            &mut v.kind,
            &mut v.length,
            &mut v.ino,
            &mut v.nlink,
            &mut v.atime_nanos,
            &mut v.mtime_nanos,
            &mut v.mode,
        )
    };
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
    let mut v = StatValues::empty();
    // SAFETY: `path` is a valid guest C string; out-pointers are local storage.
    let rc = unsafe {
        patina_metadata_at(
            dirfd as c_int,
            path,
            flags,
            &mut v.kind,
            &mut v.length,
            &mut v.ino,
            &mut v.nlink,
            &mut v.atime_nanos,
            &mut v.mtime_nanos,
            &mut v.mode,
        )
    };
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

/// The `*at` metadata flag set both `newfstatat` and `statx` accept, mirroring
/// the C `PATINA_STAT_AT_FLAGS`.
pub(super) const STAT_AT_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT;

/// Resolve the addressing forms the `*at` metadata rows accept onto the same
/// virtual metadata `stat` answers from, mirroring the C
/// `patina_stat_at_values`:
///
/// - `AT_EMPTY_PATH` with an empty path on a descriptor — the DESCRIPTOR's own
///   metadata (`File::metadata()` on Linux is exactly this);
/// - `AT_EMPTY_PATH` with an empty path on `AT_FDCWD` — the working directory;
/// - everything else — the resolved path, `AT_SYMLINK_NOFOLLOW` naming a
///   trailing symlink itself.
pub(super) fn stat_at_values(
    dirfd: i64,
    path: u64,
    flags: u64,
    allowed: u64,
) -> Result<StatValues, i64> {
    if flags & !allowed != 0 {
        return Err(-ENOSYS);
    }
    if dirfd != AT_FDCWD && is_empty_path(path, flags) {
        return fd_stat_values(dirfd as c_int);
    }
    path_stat_values(dirfd, path, resolve_flags(flags))
}

pub(super) fn sys_newfstatat(dirfd: i64, path: u64, statbuf: u64, flags: u64) -> i64 {
    if let Some(err) = fd_out_of_range(dirfd).filter(|_| dirfd != AT_FDCWD) {
        return err;
    }
    match stat_at_values(dirfd, path, flags, STAT_AT_FLAGS) {
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

pub(super) fn sys_statx(dirfd: i64, path: u64, flags: u64, statxbuf: u64) -> i64 {
    if statxbuf == 0 {
        return -EFAULT;
    }
    if let Some(err) = fd_out_of_range(dirfd).filter(|_| dirfd != AT_FDCWD) {
        return err;
    }
    let allowed = STAT_AT_FLAGS | AT_STATX_SYNC_AS_STAT | AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC;
    let values = match stat_at_values(dirfd, path, flags, allowed) {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    // STATX_{TYPE|MODE|NLINK|INO|SIZE|ATIME|MTIME|CTIME} — the exact mask the C
    // statx interposer reports.
    const STATX_MASK: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0100 | 0x0200 | 0x0020 | 0x0040 | 0x0080;
    let mut stx = Statx::default();
    stx.stx_mask = STATX_MASK;
    stx.stx_mode = stat_mode(&values) as u16;
    stx.stx_nlink = values.nlink;
    stx.stx_ino = values.ino;
    stx.stx_size = values.length;
    stx.stx_atime = StatxTimestamp {
        tv_sec: (values.atime_nanos / NANOS_PER_SEC) as i64,
        tv_nsec: (values.atime_nanos % NANOS_PER_SEC) as u32,
        __reserved: 0,
    };
    stx.stx_mtime = StatxTimestamp {
        tv_sec: (values.mtime_nanos / NANOS_PER_SEC) as i64,
        tv_nsec: (values.mtime_nanos % NANOS_PER_SEC) as u32,
        __reserved: 0,
    };
    stx.stx_ctime = stx.stx_mtime;
    // SAFETY: `statxbuf` is the guest's `struct statx` storage.
    unsafe { (statxbuf as *mut Statx).write(stx) };
    0
}

// ---- getdents64 ----

pub(super) fn dt_for_kind(kind: u32) -> u8 {
    match kind {
        PATINA_ENTRY_DIRECTORY => DT_DIR,
        PATINA_ENTRY_SYMLINK => DT_LNK,
        PATINA_ENTRY_FIFO => DT_FIFO,
        _ => DT_REG,
    }
}

/// Fill the guest buffer with `linux_dirent64` records from the fd's snapshot,
/// advancing `patina_read_dir_next` past every entry that fits. Returns the
/// number of bytes written (0 at end-of-directory) or `-errno`.
pub(super) fn sys_getdents64(fd: i64, dirp: u64, count: u64) -> i64 {
    // Linux directory iteration needs a directory descriptor: a number that
    // names nothing is EBADF, anything else (a file, a socket) is ENOTDIR.
    match fd_kind(fd) {
        None => return -EBADF,
        Some(PATINA_FD_DIR) => {}
        Some(_) => return -ENOTDIR,
    }
    if dirp == 0 {
        return -EFAULT;
    }
    let cap = count as usize;
    // The snapshot is taken by the FIRST getdents64 on the descriptor (and after
    // a rewind), through the same `patina_read_dir` entry the interposed
    // `opendir` uses — a second caller, never a second directory model.
    let mut map = DIR_ITERATIONS.lock().unwrap();
    if let std::collections::btree_map::Entry::Vacant(slot) = map.entry(fd as c_int) {
        let Ok(fd) = c_int::try_from(fd) else {
            return -EBADF;
        };
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
        slot.insert(DirIteration {
            snapshot: snapshot as usize,
            pending: None,
        });
    }
    let dir = map.get_mut(&(fd as c_int)).expect("snapshot just inserted");
    let snapshot = dir.snapshot as *mut c_void;
    let mut written = 0usize;
    // linux_dirent64 header: d_ino(8) d_off(8) d_reclen(2) d_type(1) then name.
    const HEADER: usize = 19;
    loop {
        // Next entry: the pushed-back one first, else consume from the snapshot.
        // `patina_read_dir_next` only advances (no peek), so an entry that does
        // not fit is stashed in `dir.pending` and never dropped.
        let (name, kind) = if let Some(entry) = dir.pending.take() {
            entry
        } else {
            let mut buf = [0u8; 256];
            let mut k: u32 = 0;
            // SAFETY: `snapshot` is the live box; `buf` is writable for its length.
            let rc = unsafe {
                patina_read_dir_next(snapshot, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut k)
            };
            match rc {
                1 => {
                    // SAFETY: `buf` now holds a NUL-terminated name.
                    let len = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) }
                        .to_bytes()
                        .len();
                    (buf[..len].to_vec(), k)
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
        let reclen = (HEADER + name.len() + 1 + 7) & !7; // 8-byte aligned
        if written + reclen > cap {
            // No room: push the entry back for the next call and stop. If nothing
            // fit at all, the caller's buffer is too small for even one entry.
            let empty = written == 0;
            dir.pending = Some((name, kind));
            if empty {
                return -EINVAL;
            }
            break;
        }
        // Commit: write the linux_dirent64 record into the guest buffer.
        // SAFETY: `dirp+written` has `reclen` bytes of room (checked above).
        unsafe {
            let rec = (dirp as *mut u8).add(written);
            // d_ino: the snapshot exposes no inode; a stable nonzero value keeps
            // callers that reject d_ino==0 happy.
            (rec as *mut u64).write((written as u64) + 1);
            (rec.add(8) as *mut i64).write((written + reclen) as i64); // d_off cookie
            (rec.add(16) as *mut u16).write(reclen as u16); // d_reclen
            rec.add(18).write(dt_for_kind(kind)); // d_type
            let dst = rec.add(HEADER);
            std::ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
            dst.add(name.len()).write(0); // NUL
        }
        written += reclen;
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

/// `mknodat(2)`, the only door a raw-syscall guest has to a FIFO: glibc's
/// `mkfifo`/`mkfifoat` are library wrappers over this number, and rustix lowers
/// its own onto it. Only `S_IFIFO` is modeled — see the C `patina_mknod_impl`,
/// whose type dispatch and deny string this mirrors byte for byte.
pub(super) fn sys_mknodat(dirfd: i64, path: u64, mode: u64, device: u64) -> i64 {
    let kind = mode & S_IFMT;
    if kind == S_IFCHR || kind == S_IFBLK {
        // What the single non-root identity this runtime models would get on a
        // real kernel; a device node is a host escape by construction.
        return -EPERM;
    }
    if kind != S_IFIFO as u64 {
        return sud_deny(DENY_MKNOD_TYPE);
    }
    if device != 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { patina_mkfifo(dirfd as c_int, path, (mode & 0o7777) as u32) })
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
/// legacy `access`). The guest is one non-root identity (uid 1000) owning every
/// modeled entry, so the answer reads the OWNER triad of the entry's modeled
/// permission bits. `X_OK` on a non-directory is refused whatever its mode:
/// nothing here can be executed, so reporting a file as runnable would be a
/// fabricated answer rather than a permission one. Mirrors the C
/// `faccessat`/`patina_access_impl` exactly, including its accepted flag set:
/// `AT_EACCESS` only chooses effective vs real ids, which are one identity here.
///
/// `cap-primitives` calls this on every `..` component
/// (`accessat(base, ".", X_OK, AT_EACCESS)`), so without it a capability-style
/// guest cannot walk out of a subdirectory at all.
pub(super) fn sys_faccessat(dirfd: i64, path: u64, mode: u64, flags: u64) -> i64 {
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW) != 0 {
        return -ENOSYS;
    }
    let values = match path_stat_values(dirfd, path, 0) {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    if mode & X_OK != 0 && values.kind != PATINA_ENTRY_DIRECTORY {
        return -EACCES;
    }
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
/// always `fchmodat2`'s. `AT_SYMLINK_NOFOLLOW` is the only defined one;
/// anything else is `EINVAL` rather than silently ignored.
pub(super) fn sys_fchmodat(dirfd: i64, path: u64, mode: u64, flags: u64) -> i64 {
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
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
    // The deterministic rename models no flags (RENAME_NOREPLACE/EXCHANGE/…);
    // a nonzero renameat2 flag fails closed, mirroring the C interposer.
    if flags != 0 {
        return -EINVAL;
    }
    let (oldpath, newpath) = match (guest_path(oldpath), guest_path(newpath)) {
        (Ok(oldpath), Ok(newpath)) => (oldpath, newpath),
        (Err(errno), _) | (_, Err(errno)) => return errno,
    };
    // SAFETY: both are valid NUL-terminated string pointers.
    ret_i32(unsafe { patina_rename(olddirfd as c_int, oldpath, newdirfd as c_int, newpath) })
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
