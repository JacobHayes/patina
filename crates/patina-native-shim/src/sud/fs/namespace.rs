//! Directory namespace mutation and access syscalls.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---- Directory namespace ops ----

pub(in crate::sud) fn sys_mkdirat(dirfd: i64, path: u64, mode: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { crate::fs::patina_mkdir(dirfd as c_int, path, (mode & 0o7777) as u32) })
}

/// `mknodat(2)`, the only door a raw-syscall guest has to a FIFO, a socket
/// node or a whiteout (glibc's `mkfifo`/`mkfifoat` are library wrappers over
/// this number, and rustix lowers its own onto it): the one entry the C
/// `mknod` calls too. The kernel reads the device as an `unsigned int`.
pub(in crate::sud) fn sys_mknodat(dirfd: i64, path: u64, mode: u64, device: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { crate::fs::patina_mknod(dirfd as c_int, path, mode as u32, device as u32) })
}

pub(in crate::sud) fn sys_unlinkat(dirfd: i64, path: u64, flags: u64) -> i64 {
    // AT_REMOVEDIR selects rmdir; no flag selects unlink; unknown flags fail.
    if flags & !AT_REMOVEDIR != 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    if flags & AT_REMOVEDIR != 0 {
        // SAFETY: `path` is a valid NUL-terminated guest string pointer.
        ret_i32(unsafe { crate::fs::patina_rmdir(dirfd as c_int, path) })
    } else {
        // SAFETY: as above.
        ret_i32(unsafe { crate::fs::patina_unlink(dirfd as c_int, path) })
    }
}

/// `symlinkat(target, newdirfd, linkpath)`. Only the LINK path is dirfd-relative
/// — `target` is the link's literal contents and is never resolved here.
pub(in crate::sud) fn sys_symlinkat(target: u64, newdirfd: i64, linkpath: u64) -> i64 {
    let (target, linkpath) = match (guest_path(target), guest_path(linkpath)) {
        (Ok(target), Ok(linkpath)) => (target, linkpath),
        (Err(errno), _) | (_, Err(errno)) => return errno,
    };
    // SAFETY: both are valid NUL-terminated string pointers.
    ret_i32(unsafe { crate::fs::patina_symlink(target, newdirfd as c_int, linkpath) })
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
pub(in crate::sud) fn sys_faccessat(dirfd: i64, path: u64, mode: u64, flags: u64) -> i64 {
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW) != 0 {
        return -EINVAL;
    }
    let values = match path_stat_values(dirfd, path, 0) {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    // The one answer the C `access` gives too.
    // SAFETY: `values` is a local record.
    -i64::from(unsafe { crate::patina_access_answer(&values, mode as c_int) })
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
pub(in crate::sud) fn sys_fchmodat(dirfd: i64, path: u64, mode: u64, flags: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe {
        crate::fs::patina_chmod(dirfd as c_int, path, mode as u32, resolve_flags(flags))
    })
}

/// Raw `fchmod` -> `patina_fchmod`. A descriptor already names the node, so
/// there is no symlink to resolve.
pub(in crate::sud) fn sys_fchmod(fd: i64, mode: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    ret_i32(crate::fs::patina_fchmod(fd as c_int, mode as u32))
}

/// Raw `linkat`/`link` -> the same deterministic hard link the `patina_link`
/// interposer creates (std::fs::hard_link lowers to
/// `linkat(AT_FDCWD, .., AT_FDCWD, .., 0)`). AT_SYMLINK_FOLLOW is the sole
/// defined flag: when set, `oldpath`'s trailing symlink is resolved before
/// linking, so a raw caller sees the identical follow/no-follow behavior as the
/// C `linkat` interposer; any other flag bit is EINVAL rather than silently
/// ignored.
pub(in crate::sud) fn sys_linkat(
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
        crate::fs::patina_link(
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
/// answer is the kernel's own for an empty path naming a non-symlink:
/// `ENOENT`. `bufsiz <= 0` is `EINVAL` before anything is resolved.
pub(in crate::sud) fn sys_readlinkat(dirfd: i64, path: u64, buf: u64, bufsize: u64) -> i64 {
    if (bufsize as i64) <= 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is valid; `buf` is writable for `bufsize`.
    crate::abi::raw(
        unsafe { crate::fs::read_link(dirfd as c_int, path, buf as *mut c_char, bufsize as usize) }
            .map(|result| result as i64),
    )
}

pub(in crate::sud) fn sys_renameat(
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
        crate::fs::patina_renameat2(
            olddirfd as c_int,
            oldpath,
            newdirfd as c_int,
            newpath,
            flags as u32,
        )
    })
}
