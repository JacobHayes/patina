//! Descriptor I/O adapters over the same model entries as raw syscalls.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::{cancel, error, model_result, size_result};
use core::ffi::{c_int, c_void};
#[cfg(target_os = "linux")]
pub(super) mod linux;

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn isatty(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    linux::isatty_impl(fd)
}
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
extern "C" fn isatty(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::errno(if crate::patina_fd_kind(fd) < 0 {
        libc::EBADF
    } else {
        libc::ENOTTY
    });
    0
}
/// # Safety
/// `destination` follows read's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn read(fd: c_int, destination: *mut c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"read");
    // SAFETY: the caller's read-buffer contract is forwarded to the model entry.
    let result = unsafe { crate::fd::patina_read(fd, destination, length) };
    crate::abi::libc_result(crate::abi::from_model(result), result)
}
/// # Safety
/// `source` follows write's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn write(fd: c_int, source: *const c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"write");
    // SAFETY: the caller's write-buffer contract is forwarded to the model entry.
    let result = unsafe { crate::fd::patina_write(fd, source, length) };
    crate::abi::libc_result(crate::abi::from_model(result), result)
}
/// # Safety
/// `destination` follows pread's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn pread(
    fd: c_int,
    destination: *mut c_void,
    length: usize,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pread");
    // SAFETY: the caller's pread-buffer contract is forwarded to the model entry.
    unsafe { size_result(crate::patina_pread(fd, destination, length, offset)) }
}
/// # Safety
/// `source` follows pwrite's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn pwrite(
    fd: c_int,
    source: *const c_void,
    length: usize,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pwrite");
    // SAFETY: the caller's pwrite-buffer contract is forwarded to the model entry.
    unsafe { size_result(crate::patina_pwrite(fd, source, length, offset)) }
}
#[unsafe(no_mangle)]
extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(crate::fd::flock(fd, operation), -1)
}
/// # Safety
/// `fd` is closed following the libc descriptor contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn close(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"close");
    crate::abi::libc_result(crate::fd::value::close(fd), -1)
}
#[unsafe(no_mangle)]
extern "C" fn dup(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(crate::fd::value::dup(fd), -1)
}
#[unsafe(no_mangle)]
extern "C" fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(crate::fd::value::dup2(oldfd, newfd), -1)
}
/// # Safety
/// `vectors` follows writev's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn writev(fd: c_int, vectors: *const libc::iovec, count: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"writev");
    // SAFETY: the caller's writev vector contract is forwarded to the model entry.
    unsafe {
        size_result(crate::iov::patina_writev(
            fd,
            vectors.cast(),
            i64::from(count),
            0,
        ))
    }
}
/// # Safety
/// `vectors` follows readv's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn readv(fd: c_int, vectors: *const libc::iovec, count: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"readv");
    // SAFETY: the caller's readv vector contract is forwarded to the model entry.
    unsafe {
        size_result(crate::iov::patina_readv(
            fd,
            vectors.cast(),
            i64::from(count),
            0,
        ))
    }
}
/// # Safety
/// `vectors` follows preadv's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn preadv(
    fd: c_int,
    vectors: *const libc::iovec,
    count: c_int,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"preadv");
    // SAFETY: the caller's preadv vector contract is forwarded to the model entry.
    unsafe {
        size_result(crate::iov::patina_preadv(
            fd,
            vectors.cast(),
            i64::from(count),
            offset,
            0,
        ))
    }
}
/// # Safety
/// `vectors` follows pwritev's buffer contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn pwritev(
    fd: c_int,
    vectors: *const libc::iovec,
    count: c_int,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pwritev");
    // SAFETY: the caller's pwritev vector contract is forwarded to the model entry.
    unsafe {
        size_result(crate::iov::patina_pwritev(
            fd,
            vectors.cast(),
            i64::from(count),
            offset,
            0,
        ))
    }
}
#[unsafe(no_mangle)]
extern "C" fn lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    seek_impl(fd, offset, whence)
}
fn seek_impl(fd: c_int, offset: i64, whence: c_int) -> i64 {
    let whence = match whence {
        libc::SEEK_SET => 0,
        libc::SEEK_CUR => 1,
        libc::SEEK_END => 2,
        libc::SEEK_DATA => 3,
        libc::SEEK_HOLE => 4,
        _ => return i64::from(error(libc::EINVAL)),
    };
    crate::abi::libc_result(crate::fd::seek(fd, offset, whence), -1)
}
#[unsafe(no_mangle)]
extern "C" fn fsync(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"fsync");
    crate::abi::libc_result(crate::fd::fsync(fd), -1)
}
#[unsafe(no_mangle)]
extern "C" fn ftruncate(fd: c_int, length: libc::off_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    truncate_impl(fd, length)
}
fn truncate_impl(fd: c_int, length: i64) -> c_int {
    if length < 0 {
        return error(libc::EINVAL);
    }
    crate::abi::libc_result(crate::fd::set_len(fd, length as u64), -1)
}
/// # Safety
/// `fildes` is null or writable for two descriptor numbers.
#[unsafe(no_mangle)]
unsafe extern "C" fn pipe(fildes: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if fildes.is_null() {
        return error(libc::EFAULT);
    }
    // SAFETY: non-null `fildes` is writable for two descriptors by the pipe contract.
    unsafe { model_result(crate::thread::patina_pipe(fildes, fildes.add(1), 0, 0)) }
}
