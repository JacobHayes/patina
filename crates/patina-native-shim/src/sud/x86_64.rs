//! SUD rows only the x86_64 table lists that need a decode of their own:
//! `dup2`, `epoll_create`, `poll`, the pre-`utimensat` time rows (`utime`,
//! `utimes`, `futimesat`), `ustat`, and the legacy `getdents`. The aarch64
//! table (asm-generic) never had these numbers — glibc there reaches `dup3`,
//! `epoll_create1`, `ppoll` and `utimensat` instead — so this module is
//! compiled exactly where the registry gives them an identity. Each lands on
//! the same `patina_*` entry as its modern row. The x86_64 rows that are pure
//! argument re-shuffles of a modern row (`open`, `stat`, `pipe`, `epoll_wait`,
//! …) bind their modern handler directly in `BINDINGS`.

use super::*;

unsafe extern "C" {
    fn patina_dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn patina_ustat(dev: u32, out: *mut c_void) -> c_int;
}

/// `ustat(2)`: the kernel reads the device as an `unsigned int`.
pub(super) fn sys_ustat(dev: u64, ubuf: u64) -> i64 {
    // SAFETY: `ubuf` is the guest's `struct ustat` storage (or NULL, EFAULT).
    ret_i32(unsafe { patina_ustat(dev as u32, ubuf as *mut c_void) })
}

/// `dup2(2)`. It differs from `dup3` in EXACTLY the equal-fd case:
/// `dup2(fd, fd)` validates `fd` and returns it unchanged (no close, no
/// CLOEXEC), whereas `dup3(fd, fd, …)` is `-EINVAL`. The entry owns that
/// distinction, so the raw and wrapped paths route identically.
pub(super) fn sys_dup2(oldfd: i64, newfd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(oldfd) {
        return err;
    }
    let newfd = c_int::try_from(newfd).unwrap_or(-1);
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_dup2(oldfd as c_int, newfd) })
}

/// `epoll_create(size)`. The `size` hint has been ignored since Linux 2.6.8,
/// but the kernel still rejects `size <= 0` with `-EINVAL` before creating the
/// instance with no flags. Everything else is `epoll_create1(0)`.
pub(super) fn sys_epoll_create(size: u64) -> i64 {
    if size as i32 <= 0 {
        return -EINVAL;
    }
    sys_epoll_create1(0)
}

/// `poll(2)`. `timeout` is an `int` of milliseconds: negative is the infinite
/// timeout, otherwise it scales to the nanoseconds the readiness core takes.
/// Unlike `ppoll`, nothing is written back.
pub(super) fn sys_poll(fds: u64, nfds: u64, timeout_ms: i64) -> i64 {
    let timeout = if timeout_ms < 0 {
        -1
    } else {
        (timeout_ms as u64)
            .saturating_mul(1_000_000)
            .min(i64::MAX as u64) as i64
    };
    // SAFETY: `fds` is the guest's array of `nfds` pollfd entries; the entry
    // checks it before reading.
    unsafe {
        crate::thread::readiness::patina_poll(
            fds as *mut _,
            nfds as usize,
            timeout,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    }
}

/// A `utimbuf` (`utime(2)`): two whole-second times.
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelUtimbuf {
    actime: i64,
    modtime: i64,
}

/// A `timeval` time argument (`utimes`/`futimesat`): microseconds in range.
fn timeval_argument(time: &Timeval) -> Result<TimeArgument, i64> {
    if !(0..1_000_000).contains(&time.tv_usec) {
        return Err(-EINVAL);
    }
    Ok((
        crate::TIME_SET,
        PatinaTimestamp {
            sec: time.tv_sec,
            nsec: time.tv_usec * 1_000,
        },
    ))
}

/// `utimes(2)` and `futimesat(2)`: microsecond times, always following a
/// trailing symlink; a null path on `futimesat` names the directory
/// descriptor itself.
pub(super) fn sys_futimesat(dirfd: i64, path: u64, times: u64) -> i64 {
    let [atime, mtime] = match times_arguments(times, timeval_argument) {
        Ok(times) => times,
        Err(errno) => return errno,
    };
    if path == 0 {
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
        patina_utimensat(dirfd as c_int, path, 0, atime.0, atime.1, mtime.0, mtime.1)
    })
}

/// `utime(2)`: whole-second times; a null buffer is now/now.
pub(super) fn sys_utime(path: u64, times: u64) -> i64 {
    let (atime, mtime) = if times == 0 {
        let now = (crate::TIME_NOW, PatinaTimestamp::default());
        (now, now)
    } else {
        // SAFETY: `times` is the guest's `struct utimbuf`.
        let buf = unsafe { (times as *const KernelUtimbuf).read_unaligned() };
        let whole = |sec| (crate::TIME_SET, PatinaTimestamp { sec, nsec: 0 });
        (whole(buf.actime), whole(buf.modtime))
    };
    let path = match guest_path(path) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    // SAFETY: `path` is a valid NUL-terminated guest string pointer.
    ret_i32(unsafe {
        patina_utimensat(
            AT_FDCWD as c_int,
            path,
            0,
            atime.0,
            atime.1,
            mtime.0,
            mtime.1,
        )
    })
}

/// The legacy `getdents(2)`: the same per-descriptor iteration `getdents64`
/// reads, in the `struct linux_dirent` layout.
pub(super) fn sys_getdents(fd: i64, dirp: u64, count: u64) -> i64 {
    getdents(fd, dirp, count, DirentFormat::Dirent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dup2_diverges_from_dup3_only_on_equal_fds() {
        // The kernel-exact divergence: dup2(fd, fd) is a validating no-op that
        // returns fd, whereas dup3(fd, fd, 0) is -EINVAL. RED: routing legacy
        // `dup2` straight through the dup3 handler (or vice versa) would turn a
        // valid stdio dup2(1,1) into -EINVAL, breaking any raw dup2-based fd
        // shuffle. The descriptor table alone answers these (no runtime is
        // installed here): the three standard numbers exist from birth.
        assert_eq!(sys_dup2(0, 0), 0);
        assert_eq!(sys_dup2(1, 1), 1);
        assert_eq!(sys_dup2(2, 2), 2);
        assert_eq!(sys_dup3(0, 0, 0), -EINVAL);
        assert_eq!(sys_dup3(1, 1, 0), -EINVAL);
        // An out-of-range equal fd is EBADF (a bad descriptor), NOT EINVAL.
        assert_eq!(sys_dup2(-1, -1), -EBADF);
        // A source that names nothing is EBADF before the target is looked at.
        assert_eq!(sys_dup2(900, 901), -EBADF);
        assert_eq!(sys_dup3(900, 901, 0), -EBADF);
        // dup3 refuses a flag other than O_CLOEXEC before touching the table.
        assert_eq!(sys_dup3(0, 901, 0o4000), -EINVAL);
        // A chosen number well above the table is EBADF.
        assert_eq!(sys_dup3(0, 1 << 20, 0), -EBADF);
    }

    #[test]
    fn epoll_create_rejects_nonpositive_size_like_the_kernel() {
        // `epoll_create(size)` ignores `size` since 2.6.8 but still rejects
        // `size <= 0` with -EINVAL before creating. RED: dropping the guard would
        // let epoll_create(0) fall through to epoll_create1 and succeed, diverging
        // from the kernel. (size > 0 delegates to the runtime and is covered
        // end-to-end by the epoll validate leg.)
        assert_eq!(sys_epoll_create(0), -EINVAL);
        assert_eq!(sys_epoll_create(0xFFFF_FFFF), -EINVAL); // reads as int -1
    }

    #[test]
    fn poll_validates_buffers_and_descriptor_limit_before_waiting() {
        assert_eq!(sys_poll(0, 1, -1), -EFAULT);
        assert_eq!(sys_poll(0, 1025, 0), -EINVAL);
    }
}
