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

#![deny(clippy::undocumented_unsafe_blocks)]

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
    let kind = crate::fd::patina_fd_kind(fd as c_int);
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
    if flags & uapi::O_NOCTTY as u64 != 0 {
        patina_flags |= PATINA_O_NOCTTY;
    }
    patina_flags
}

/// The kernel `open(2)` flag bits the deterministic filesystem models. Mirrors
/// `patina_openat_impl`'s `supported` mask exactly: a bit outside it names
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
    | O_NONBLOCK
    | uapi::O_NOCTTY as u64;

/// Every flag `open(2)` defines (`VALID_OPEN_FLAGS`): what `openat2` accepts
/// before refusing the rest, where `openat` silently drops unknown bits.
const OPEN_VALID_FLAGS: u64 = OPENAT_SUPPORTED_FLAGS
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
        crate::fs::patina_openat2(
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
        crate::fs::patina_openat(
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
        unsafe { crate::fs::free_dir(iteration.snapshot as *mut c_void) };
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
        unsafe { crate::fs::free_dir(dir.snapshot as *mut c_void) };
    }
    Some(target)
}

mod dirents;
mod metadata;
mod namespace;
mod process_state;
mod xattr;

#[cfg(test)]
mod tests;

pub(super) use dirents::{sys_getdents64, sys_name_to_handle_at};
// The legacy x86_64-only syscalls in `super::x86_64` share these helpers.
#[cfg(target_arch = "x86_64")]
pub(super) use dirents::{DirentFormat, getdents};
#[cfg(test)]
pub(super) use metadata::STAT_AT_FLAGS;
use metadata::STATX_MNT_ID_VALUE;
pub(super) use metadata::{
    fd_stat_values, path_stat_values, sys_fstat, sys_fstatfs, sys_newfstatat, sys_statfs, sys_statx,
};
pub(super) use namespace::{
    sys_faccessat, sys_fchmod, sys_fchmodat, sys_linkat, sys_mkdirat, sys_mknodat, sys_readlinkat,
    sys_renameat, sys_symlinkat, sys_unlinkat,
};
#[cfg(target_arch = "x86_64")]
pub(super) use process_state::{TimeArgument, times_arguments};
pub(super) use process_state::{
    sys_chdir, sys_fallocate, sys_fchdir, sys_fchown, sys_fchownat, sys_getcwd, sys_truncate,
    sys_umask, sys_utimensat,
};
pub(super) use xattr::{
    sys_fgetxattr, sys_flistxattr, sys_fremovexattr, sys_fsetxattr, sys_getxattr, sys_listxattr,
    sys_removexattr, sys_setxattr,
};
