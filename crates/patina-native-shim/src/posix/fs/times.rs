//! libc timestamp spellings lower to the model's three time argument kinds.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::PatinaTimestamp;

unsafe fn timespec_argument(time: *const libc::timespec) -> Result<(u32, PatinaTimestamp), c_int> {
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        let zero = PatinaTimestamp { sec: 0, nsec: 0 };
        if time.is_null() {
            return Ok((crate::TIME_NOW, zero));
        }
        if (*time).tv_nsec == libc::UTIME_NOW {
            return Ok((crate::TIME_NOW, zero));
        }
        if (*time).tv_nsec == libc::UTIME_OMIT {
            return Ok((crate::TIME_OMIT, zero));
        }
        if (*time).tv_nsec < 0 || (*time).tv_nsec > 999999999 {
            return Err(error(libc::EINVAL));
        }
        Ok((
            crate::TIME_SET,
            PatinaTimestamp {
                sec: (*time).tv_sec as libc::time_t,
                nsec: (*time).tv_nsec as libc::time_t,
            },
        ))
    }
}
unsafe fn timeval_argument(time: *const libc::timeval) -> Result<(u32, PatinaTimestamp), c_int> {
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        let zero = PatinaTimestamp { sec: 0, nsec: 0 };
        if time.is_null() {
            return Ok((crate::TIME_NOW, zero));
        }
        if (*time).tv_usec < 0 || (*time).tv_usec > 999999 {
            return Err(error(libc::EINVAL));
        }
        Ok((
            crate::TIME_SET,
            PatinaTimestamp {
                sec: (*time).tv_sec as libc::time_t,
                nsec: (*time).tv_usec as libc::time_t * 1000,
            },
        ))
    }
}
unsafe fn utimens_impl(
    directory: c_int,
    path: *const c_char,
    times: *const libc::timespec,
    flags: u32,
) -> c_int {
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        let (atime_kind, atime) = match timespec_argument(times) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let second = if times.is_null() { times } else { times.add(1) };
        let (mtime_kind, mtime) = match timespec_argument(second) {
            Ok(value) => value,
            Err(result) => return result,
        };
        crate::abi::libc_result(
            crate::abi::from_model(crate::patina_utimensat(
                directory, path, flags, atime_kind, atime, mtime_kind, mtime,
            )),
            -1,
        )
    }
}
unsafe fn utimes_impl(
    directory: c_int,
    path: *const c_char,
    times: *const libc::timeval,
    flags: u32,
) -> c_int {
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        let (atime_kind, atime) = match timeval_argument(times) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let second = if times.is_null() { times } else { times.add(1) };
        let (mtime_kind, mtime) = match timeval_argument(second) {
            Ok(value) => value,
            Err(result) => return result,
        };
        crate::abi::libc_result(
            crate::abi::from_model(crate::patina_utimensat(
                directory, path, flags, atime_kind, atime, mtime_kind, mtime,
            )),
            -1,
        )
    }
}

/// # Safety
/// Guest pointers satisfy the corresponding libc time/string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn utimensat(
    directory: c_int,
    path: *const c_char,
    times: *const libc::timespec,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if path.is_null() {
        return error(libc::EINVAL);
    }
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        if !times.is_null()
            && (*times).tv_nsec == libc::UTIME_OMIT
            && (*times.add(1)).tv_nsec == libc::UTIME_OMIT
        {
            return utimens_impl(at(directory), path, times, 0);
        }
        if flags & !(libc::AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return error(libc::EINVAL);
        }
        let resolve_flags = if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
            RESOLVE_NOFOLLOW
        } else {
            0
        };
        #[cfg(target_os = "linux")]
        let resolve_flags = resolve_flags
            | if flags & AT_EMPTY_PATH != 0 {
                RESOLVE_EMPTY_PATH
            } else {
                0
            };
        utimens_impl(at(directory), path, times, resolve_flags)
    }
}

/// # Safety
/// The guest timestamp array satisfies libc futimens's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn futimens(fd: c_int, times: *const libc::timespec) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        let (atime_kind, atime) = match timespec_argument(times) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let second = if times.is_null() { times } else { times.add(1) };
        let (mtime_kind, mtime) = match timespec_argument(second) {
            Ok(value) => value,
            Err(result) => return result,
        };
        crate::abi::libc_result(
            crate::abi::from_model(crate::patina_futimens(
                fd, atime_kind, atime, mtime_kind, mtime,
            )),
            -1,
        )
    }
}

/// # Safety
/// Guest pointers satisfy the corresponding libc time/string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn utimes(path: *const c_char, times: *const libc::timeval) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe { utimes_impl(AT_FDCWD, path, times, 0) }
}

/// # Safety
/// Guest pointers satisfy the corresponding libc time/string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lutimes(path: *const c_char, times: *const libc::timeval) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe { utimes_impl(AT_FDCWD, path, times, RESOLVE_NOFOLLOW) }
}

/// # Safety
/// The guest timestamp array satisfies libc futimes's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn futimes(fd: c_int, times: *const libc::timeval) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        let (atime_kind, atime) = match timeval_argument(times) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let second = if times.is_null() { times } else { times.add(1) };
        let (mtime_kind, mtime) = match timeval_argument(second) {
            Ok(value) => value,
            Err(result) => return result,
        };
        crate::abi::libc_result(
            crate::abi::from_model(crate::patina_futimens(
                fd, atime_kind, atime, mtime_kind, mtime,
            )),
            -1,
        )
    }
}

/// # Safety
/// Guest pointers satisfy the corresponding libc time/string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn utime(path: *const c_char, times: *const libc::utimbuf) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        if times.is_null() {
            return utimens_impl(AT_FDCWD, path, core::ptr::null(), 0);
        }
        let atime = PatinaTimestamp {
            sec: (*times).actime as libc::time_t,
            nsec: 0,
        };
        let mtime = PatinaTimestamp {
            sec: (*times).modtime as libc::time_t,
            nsec: 0,
        };
        crate::abi::libc_result(
            crate::abi::from_model(crate::patina_utimensat(
                AT_FDCWD,
                path,
                0,
                crate::TIME_SET,
                atime,
                crate::TIME_SET,
                mtime,
            )),
            -1,
        )
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Guest pointers satisfy the corresponding libc time/string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn futimesat(
    directory: c_int,
    path: *const c_char,
    times: *const libc::timeval,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: The timestamp arrays and path pointers satisfy this libc operation’s documented contract.
    unsafe {
        if path.is_null() {
            return futimes(directory, times);
        }
        utimes_impl(at(directory), path, times, 0)
    }
}
