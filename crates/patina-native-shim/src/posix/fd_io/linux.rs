//! Linux large-file, fortify, transfer, and pipe adapters.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::{cancel, error, model_result, size_result};
use core::ffi::{c_int, c_void};
mod terminal;
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pread64(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    offset: libc::off64_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pread64");
    // SAFETY: the caller's buffer contract is forwarded to the model entry.
    unsafe { size_result(crate::patina_pread(fd, buffer, length, offset)) }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwrite64(
    fd: c_int,
    buffer: *const c_void,
    length: usize,
    offset: libc::off64_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pwrite64");
    // SAFETY: the caller's buffer contract is forwarded to the model entry.
    unsafe { size_result(crate::patina_pwrite(fd, buffer, length, offset)) }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __read(fd: c_int, buffer: *mut c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's read-buffer contract is forwarded to the model entry.
    let result = unsafe { crate::fd::patina_read(fd, buffer, length) };
    crate::abi::libc_result(crate::abi::from_model(result), result)
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __write(fd: c_int, buffer: *const c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's write-buffer contract is forwarded to the model entry.
    let result = unsafe { crate::fd::patina_write(fd, buffer, length) };
    crate::abi::libc_result(crate::abi::from_model(result), result)
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __read_chk(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    buflen: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__read_chk");
    // SAFETY: the caller's read-buffer contract is forwarded after fortify checks.
    unsafe {
        if length > buflen {
            crate::posix::chk_fail();
        }
        let result = crate::fd::patina_read(fd, buffer, length);
        crate::abi::libc_result(crate::abi::from_model(result), result)
    }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __pread_chk(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    offset: libc::off_t,
    buflen: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__pread_chk");
    // SAFETY: the caller's pread-buffer contract is forwarded after fortify checks.
    unsafe {
        if length > buflen {
            crate::posix::chk_fail();
        }
        size_result(crate::patina_pread(fd, buffer, length, offset))
    }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __pread64_chk(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    offset: libc::off64_t,
    buflen: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__pread64_chk");
    // SAFETY: the caller's pread64-buffer contract is forwarded after fortify checks.
    unsafe {
        if length > buflen {
            crate::posix::chk_fail();
        }
        size_result(crate::patina_pread(fd, buffer, length, offset))
    }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_file_range(
    fd_in: c_int,
    off_in: *mut libc::off64_t,
    fd_out: c_int,
    off_out: *mut libc::off64_t,
    length: usize,
    flags: libc::c_uint,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"copy_file_range");
    // SAFETY: offset pointers are forwarded under copy_file_range's caller contract.
    unsafe {
        size_result(crate::transfer::patina_copy_file_range(
            fd_in, off_in, fd_out, off_out, length, flags,
        ))
    }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut libc::off_t,
    count: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the offset pointer is forwarded under sendfile's caller contract.
    unsafe {
        size_result(crate::transfer::patina_sendfile(
            out_fd, in_fd, offset, count,
        ))
    }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendfile64(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut libc::off64_t,
    count: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the offset pointer is forwarded under sendfile64's caller contract.
    unsafe {
        size_result(crate::transfer::patina_sendfile(
            out_fd, in_fd, offset, count,
        ))
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn dup3(oldfd: c_int, newfd: c_int, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !libc::O_CLOEXEC != 0 {
        return error(libc::EINVAL);
    }
    crate::abi::libc_result(
        crate::fd::value::dup3(oldfd, newfd, c_int::from(flags & libc::O_CLOEXEC != 0)),
        -1,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn close_range(first: libc::c_uint, last: libc::c_uint, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(crate::fd::patina_close_range(first, last, flags as u32))
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn preadv64(
    fd: c_int,
    vectors: *const libc::iovec,
    count: c_int,
    offset: libc::off64_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"preadv64");
    // SAFETY: the caller's preadv64 vector contract is forwarded to the model entry.
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
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwritev64(
    fd: c_int,
    vectors: *const libc::iovec,
    count: c_int,
    offset: libc::off64_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"pwritev64");
    // SAFETY: the caller's pwritev64 vector contract is forwarded to the model entry.
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
pub extern "C" fn fdatasync(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"fdatasync");
    crate::abi::libc_result(crate::fd::fsync(fd), -1)
}
#[unsafe(no_mangle)]
pub extern "C" fn lseek64(fd: c_int, offset: libc::off64_t, whence: c_int) -> libc::off64_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::seek_impl(fd, offset, whence)
}
#[unsafe(no_mangle)]
pub extern "C" fn ftruncate64(fd: c_int, length: libc::off64_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::truncate_impl(fd, length)
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe2(pipefd: *mut c_int, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let invalid = flags & !(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_DIRECT);
    if invalid != 0 {
        return error(libc::EINVAL);
    }
    if flags & libc::O_DIRECT != 0 {
        return error(libc::ENOSYS);
    }
    let nonblocking = c_int::from(flags & libc::O_NONBLOCK != 0);
    let cloexec = c_int::from(flags & libc::O_CLOEXEC != 0);
    let mut fds = [0; 2];
    // SAFETY: `fds` is local writable storage for the two pipe descriptors.
    let result =
        unsafe { crate::thread::patina_pipe(&mut fds[0], &mut fds[1], nonblocking, cloexec) };
    if result != 0 {
        return model_result(result);
    }
    match crate::uaccess::write(pipefd as usize, &fds) {
        Ok(()) => 0,
        Err(errno) => {
            let _ = crate::fd::value::close(fds[0]);
            let _ = crate::fd::value::close(fds[1]);
            crate::abi::libc_result(Err(crate::abi::failed(errno)), -1)
        }
    }
}

pub(in crate::posix) use terminal::isatty_impl;
