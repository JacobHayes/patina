//! Working-directory, umask, timestamp, ownership, and size syscalls.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---- The working directory and the umask ----

/// `getcwd(2)`: kernel semantics, not glibc's. The directory's current name is
/// copied NUL-terminated into `buf` and the byte count INCLUDING the terminator
/// is returned; a buffer too small (including `size == 0`) is `ERANGE`, and an
/// unlinked working directory is `ENOENT`.
pub(in crate::sud) fn sys_getcwd(buf: u64, size: u64) -> i64 {
    if buf == 0 {
        return -EFAULT;
    }
    if size == 0 {
        return -ERANGE;
    }
    // SAFETY: `buf` is the guest's buffer, writable for `size` bytes.
    let length = unsafe { crate::fs::patina_getcwd(buf as *mut c_char, size as usize) };
    if length < 0 {
        return -(crate::environment::patina_errno() as i64);
    }
    length as i64 + 1
}

/// `chdir(2)` -> the same working-directory state the C interposer sets.
pub(in crate::sud) fn sys_chdir(path: u64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { crate::fs::patina_chdir(AT_FDCWD as c_int, path) })
}

/// `fchdir(2)`.
pub(in crate::sud) fn sys_fchdir(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    ret_i32(crate::fs::patina_fchdir(fd as c_int))
}

/// `umask(2)`: never fails; answers the previous mask.
pub(in crate::sud) fn sys_umask(mask: u64) -> i64 {
    i64::from(crate::fs::patina_umask(mask as u32))
}

// ---- Timestamps, ownership and sizes ----

/// A kernel `struct __kernel_timespec` / `struct timespec` (x86_64: two i64).
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelTimespec {
    pub(super) tv_sec: i64,
    pub(super) tv_nsec: i64,
}

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::KernelTimespec {
        tv_sec: i64,
        tv_nsec: i64,
    });
}

/// A time argument on the runtime's `PATINA_TIME_*` vocabulary.
pub(in crate::sud) type TimeArgument = (u32, PatinaTimestamp);

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
pub(in crate::sud) fn times_arguments<T: Copy>(
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
pub(in crate::sud) fn sys_utimensat(dirfd: i64, path: u64, times: u64, flags: u64) -> i64 {
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
        return crate::abi::raw(
            crate::abi::from_model(crate::fs::patina_futimens(
                dirfd as c_int,
                atime.0,
                atime.1,
                mtime.0,
                mtime.1,
            ))
            .map(i64::from),
        );
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    crate::abi::raw(
        crate::abi::from_model(unsafe {
            crate::fs::patina_utimensat(
                dirfd as c_int,
                path,
                resolve_flags(flags),
                atime.0,
                atime.1,
                mtime.0,
                mtime.1,
            )
        })
        .map(i64::from),
    )
}

/// `fchownat(2)`, and the x86_64 legacy `chown`/`lchown`: `AT_SYMLINK_NOFOLLOW`
/// and `AT_EMPTY_PATH` are the flags (`EINVAL` otherwise). The ids are the
/// kernel's `uid_t`/`gid_t` (`-1` = unchanged), passed through as the 32-bit
/// values they are.
pub(in crate::sud) fn sys_fchownat(dirfd: i64, path: u64, uid: u64, gid: u64, flags: u64) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe {
        crate::fs::patina_chown(
            dirfd as c_int,
            path,
            resolve_flags(flags),
            uid as u32,
            gid as u32,
        )
    })
}

/// `fchown(2)`.
pub(in crate::sud) fn sys_fchown(fd: i64, uid: u64, gid: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    ret_i32(crate::fs::patina_fchown(
        fd as c_int,
        uid as u32,
        gid as u32,
    ))
}

/// `truncate(2)`: by name, following a trailing symlink.
pub(in crate::sud) fn sys_truncate(path: u64, length: i64) -> i64 {
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe { crate::fs::patina_truncate(AT_FDCWD as c_int, path, length) })
}

/// `fallocate(2)`: the mode word is the kernel's; the one entry decodes it.
pub(in crate::sud) fn sys_fallocate(fd: i64, mode: u64, offset: i64, length: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    ret_i32(crate::fs::patina_fallocate(
        fd as c_int,
        mode as u32,
        offset,
        length,
    ))
}
