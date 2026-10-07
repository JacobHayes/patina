//! Linux large-file, fortify, transfer, and pipe adapters.
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
    unsafe { size_result(crate::patina_pwrite(fd, buffer, length, offset)) }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __read(fd: c_int, buffer: *mut c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { size_result(crate::patina_read(fd, buffer, length)) }
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __write(fd: c_int, buffer: *const c_void, length: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { size_result(crate::patina_write(fd, buffer, length)) }
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
    unsafe {
        if length > buflen {
            crate::posix::chk_fail();
        }
        size_result(crate::patina_read(fd, buffer, length))
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
    model_result(crate::patina_dup3(
        oldfd,
        newfd,
        c_int::from(flags & libc::O_CLOEXEC != 0),
    ))
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
    model_result(crate::patina_fsync(fd))
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
    unsafe {
        if pipefd.is_null() {
            return error(libc::EFAULT);
        }
        let nonblocking = c_int::from(flags & libc::O_NONBLOCK != 0);
        let cloexec = c_int::from(flags & libc::O_CLOEXEC != 0);
        let mut remaining = flags & !(libc::O_NONBLOCK | libc::O_CLOEXEC);
        if remaining & libc::O_DIRECT != 0 {
            return error(libc::ENOSYS);
        }
        remaining &= !libc::O_DIRECT;
        if remaining != 0 {
            return error(libc::EINVAL);
        }
        model_result(crate::thread::patina_pipe(
            pipefd,
            pipefd.add(1),
            nonblocking,
            cloexec,
        ))
    }
}

pub(in crate::posix) use terminal::isatty_impl;
core::arch::global_asm!(
    ".globl patina_route_pread64",
    ".hidden patina_route_pread64",
    ".set patina_route_pread64, pread64",
    ".globl patina_route_pwrite64",
    ".hidden patina_route_pwrite64",
    ".set patina_route_pwrite64, pwrite64",
    ".globl patina_route___read",
    ".hidden patina_route___read",
    ".set patina_route___read, __read",
    ".globl patina_route___write",
    ".hidden patina_route___write",
    ".set patina_route___write, __write",
    ".globl patina_route___read_chk",
    ".hidden patina_route___read_chk",
    ".set patina_route___read_chk, __read_chk",
    ".globl patina_route___pread_chk",
    ".hidden patina_route___pread_chk",
    ".set patina_route___pread_chk, __pread_chk",
    ".globl patina_route___pread64_chk",
    ".hidden patina_route___pread64_chk",
    ".set patina_route___pread64_chk, __pread64_chk",
    ".globl patina_route_copy_file_range",
    ".hidden patina_route_copy_file_range",
    ".set patina_route_copy_file_range, copy_file_range",
    ".globl patina_route_sendfile",
    ".hidden patina_route_sendfile",
    ".set patina_route_sendfile, sendfile",
    ".globl patina_route_sendfile64",
    ".hidden patina_route_sendfile64",
    ".set patina_route_sendfile64, sendfile64",
    ".globl patina_route_dup3",
    ".hidden patina_route_dup3",
    ".set patina_route_dup3, dup3",
    ".globl patina_route_close_range",
    ".hidden patina_route_close_range",
    ".set patina_route_close_range, close_range",
    ".globl patina_route_preadv64",
    ".hidden patina_route_preadv64",
    ".set patina_route_preadv64, preadv64",
    ".globl patina_route_pwritev64",
    ".hidden patina_route_pwritev64",
    ".set patina_route_pwritev64, pwritev64",
    ".globl patina_route_fdatasync",
    ".hidden patina_route_fdatasync",
    ".set patina_route_fdatasync, fdatasync",
    ".globl patina_route_lseek64",
    ".hidden patina_route_lseek64",
    ".set patina_route_lseek64, lseek64",
    ".globl patina_route_ftruncate64",
    ".hidden patina_route_ftruncate64",
    ".set patina_route_ftruncate64, ftruncate64",
    ".globl patina_route_pipe2",
    ".hidden patina_route_pipe2",
    ".set patina_route_pipe2, pipe2",
);
