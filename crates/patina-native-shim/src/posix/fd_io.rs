//! Descriptor I/O adapters over the same model entries as raw syscalls.
use super::{cancel, error, model_result, size_result};
use core::ffi::{c_int, c_void};
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn isatty(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    linux::isatty_impl(fd)
}
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub extern "C" fn isatty(fd: c_int) -> c_int {
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
pub unsafe extern "C" fn read(fd: c_int, destination: *mut c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"read");
    unsafe { size_result(crate::patina_read(fd, destination, length)) }
}
/// # Safety
/// `source` follows write's buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: c_int, source: *const c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"write");
    unsafe { size_result(crate::patina_write(fd, source, length)) }
}
/// # Safety
/// `destination` follows pread's buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pread(
    fd: c_int,
    destination: *mut c_void,
    length: usize,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pread");
    unsafe { size_result(crate::patina_pread(fd, destination, length, offset)) }
}
/// # Safety
/// `source` follows pwrite's buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwrite(
    fd: c_int,
    source: *const c_void,
    length: usize,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pwrite");
    unsafe { size_result(crate::patina_pwrite(fd, source, length, offset)) }
}
#[unsafe(no_mangle)]
pub extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::patina_flock(fd, operation))
}
/// # Safety
/// `fd` is closed following the libc descriptor contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"close");
    model_result(crate::patina_close(fd))
}
#[unsafe(no_mangle)]
pub extern "C" fn dup(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::patina_dup(fd))
}
#[unsafe(no_mangle)]
pub extern "C" fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::patina_dup2(oldfd, newfd))
}
/// # Safety
/// `vectors` follows writev's buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn writev(fd: c_int, vectors: *const libc::iovec, count: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"writev");
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
pub unsafe extern "C" fn readv(fd: c_int, vectors: *const libc::iovec, count: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"readv");
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
pub unsafe extern "C" fn preadv(
    fd: c_int,
    vectors: *const libc::iovec,
    count: c_int,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"preadv");
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
pub unsafe extern "C" fn pwritev(
    fd: c_int,
    vectors: *const libc::iovec,
    count: c_int,
    offset: libc::off_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pwritev");
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
pub extern "C" fn lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
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
    let result = crate::patina_seek(fd, offset, whence);
    if result < 0 {
        super::errno(crate::patina_errno());
    }
    result
}
#[unsafe(no_mangle)]
pub extern "C" fn fsync(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"fsync");
    model_result(crate::patina_fsync(fd))
}
#[unsafe(no_mangle)]
pub extern "C" fn ftruncate(fd: c_int, length: libc::off_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    truncate_impl(fd, length)
}
fn truncate_impl(fd: c_int, length: i64) -> c_int {
    if length < 0 {
        return error(libc::EINVAL);
    }
    model_result(crate::patina_set_len(fd, length as u64))
}
/// # Safety
/// `fildes` is null or writable for two descriptor numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe(fildes: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if fildes.is_null() {
        return error(libc::EFAULT);
    }
    unsafe { model_result(crate::thread::patina_pipe(fildes, fildes.add(1), 0, 0)) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_isatty",
    ".hidden patina_route_isatty",
    ".set patina_route_isatty, isatty",
    ".globl patina_route_read",
    ".hidden patina_route_read",
    ".set patina_route_read, read",
    ".globl patina_route_write",
    ".hidden patina_route_write",
    ".set patina_route_write, write",
    ".globl patina_route_pread",
    ".hidden patina_route_pread",
    ".set patina_route_pread, pread",
    ".globl patina_route_pwrite",
    ".hidden patina_route_pwrite",
    ".set patina_route_pwrite, pwrite",
    ".globl patina_route_flock",
    ".hidden patina_route_flock",
    ".set patina_route_flock, flock",
    ".globl patina_route_close",
    ".hidden patina_route_close",
    ".set patina_route_close, close",
    ".globl patina_route_dup",
    ".hidden patina_route_dup",
    ".set patina_route_dup, dup",
    ".globl patina_route_dup2",
    ".hidden patina_route_dup2",
    ".set patina_route_dup2, dup2",
    ".globl patina_route_writev",
    ".hidden patina_route_writev",
    ".set patina_route_writev, writev",
    ".globl patina_route_readv",
    ".hidden patina_route_readv",
    ".set patina_route_readv, readv",
    ".globl patina_route_preadv",
    ".hidden patina_route_preadv",
    ".set patina_route_preadv, preadv",
    ".globl patina_route_pwritev",
    ".hidden patina_route_pwritev",
    ".set patina_route_pwritev, pwritev",
    ".globl patina_route_lseek",
    ".hidden patina_route_lseek",
    ".set patina_route_lseek, lseek",
    ".globl patina_route_fsync",
    ".hidden patina_route_fsync",
    ".set patina_route_fsync, fsync",
    ".globl patina_route_ftruncate",
    ".hidden patina_route_ftruncate",
    ".set patina_route_ftruncate, ftruncate",
    ".globl patina_route_pipe",
    ".hidden patina_route_pipe",
    ".set patina_route_pipe, pipe",
);
