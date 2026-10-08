#![deny(clippy::undocumented_unsafe_blocks)]

//! Typed descriptor-value operations shared by libc and SUD doors.

use super::*;

#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) fn dup(raw_fd: c_int) -> crate::abi::SysResult<c_int> {
    dupfd(raw_fd, 0, 0)
}

pub(crate) fn dupfd(raw_fd: c_int, minimum: c_int, cloexec: c_int) -> crate::abi::SysResult<c_int> {
    match fd_table().lock().dup(raw_fd, minimum, cloexec != 0) {
        Ok(number) => {
            set_errno(0);
            Ok(number)
        }
        Err(errno) => Err(crate::abi::failed(errno)),
    }
}

#[unsafe(no_mangle)]
/// `fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC`: the lowest free number at or above
/// `minimum`. `EINVAL` for a minimum outside the table, `EMFILE` when nothing
/// at or above it is free.
pub extern "C" fn patina_dupfd(raw_fd: c_int, minimum: c_int, cloexec: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    dupfd(raw_fd, minimum, cloexec).unwrap_or(-1)
}

#[cfg(any(patina_posix_exports, all(target_os = "linux", target_arch = "x86_64")))]
pub(crate) fn dup2(oldfd: c_int, newfd: c_int) -> crate::abi::SysResult<c_int> {
    if oldfd == newfd {
        return match resolve_fd(oldfd) {
            Ok(_) => {
                set_errno(0);
                Ok(newfd)
            }
            Err(errno) => Err(crate::abi::failed(errno)),
        };
    }
    dup3(oldfd, newfd, 0)
}

#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) fn dup3(oldfd: c_int, newfd: c_int, cloexec: c_int) -> crate::abi::SysResult<c_int> {
    // Binding over an open `newfd` closes it, which releases POSIX locks.
    if oldfd != newfd && resolve_fd(oldfd).is_ok() {
        release_posix_locks(newfd);
    }
    let released = match fd_table().lock().dup3(oldfd, newfd, cloexec != 0) {
        Ok(released) => released,
        Err(errno) => return Err(crate::abi::failed(errno)),
    };
    retire_number(newfd);
    if let Some(release) = released {
        let _ = release_description(release);
    }
    set_errno(0);
    Ok(newfd)
}

pub(crate) fn close(raw_fd: c_int) -> crate::abi::SysResult<c_int> {
    release_posix_locks(raw_fd);
    let released = match fd_table().lock().close(raw_fd) {
        Ok(released) => released,
        Err(errno) => return Err(crate::abi::failed(errno)),
    };
    retire_number(raw_fd);
    let result = match released {
        Some(release) => release_description(release),
        None => Ok(()),
    };
    match result {
        Ok(()) => {
            set_errno(0);
            Ok(0)
        }
        Err(errno) => Err(crate::abi::failed(errno)),
    }
}

#[unsafe(no_mangle)]
/// `close(2)`: free the number; the description is freed with its last number.
/// `EBADF` for a number that names nothing.
pub extern "C" fn patina_close(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    close(raw_fd).unwrap_or(-1)
}
