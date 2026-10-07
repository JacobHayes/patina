//! Guest-only ordinary POSIX adapters. Host dependency builds omit this module.
use core::ffi::CStr;
use core::ffi::c_int;

mod entropy;
mod fd_io;
mod fs;
#[cfg(target_os = "linux")]
mod memory;
mod net;
mod privileged;
mod readiness;
mod sched_identity;
mod signal_process;
pub(crate) mod stdio;

pub(crate) use crate::variadic::{error, model_result};

pub(crate) fn size_result(result: isize) -> isize {
    if result < 0 {
        error(crate::patina_errno());
    }
    result
}

pub(crate) fn cancel(name: &CStr) {
    #[cfg(target_os = "linux")]
    unsafe {
        crate::thread::cancel::patina_cancel_point(name.as_ptr());
    }
    #[cfg(target_os = "macos")]
    let _ = name;
}

#[cfg(target_os = "linux")]
#[unsafe(export_name = "patina_signal_result")]
pub extern "C" fn signal_result(result: i64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::thread::signals::patina_signal_deliver();
    if result < 0 {
        error(-result as c_int)
    } else {
        result as c_int
    }
}
#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_signal_result");

pub(crate) use crate::variadic::errno;

#[cfg(target_os = "linux")]
pub(crate) fn fortify_fail(message: &CStr) -> ! {
    let head = b"*** ";
    let tail = b" ***: terminated\n";
    let mut line = [0u8; 128];
    line[..head.len()].copy_from_slice(head);
    let mut at = head.len();
    for &byte in message.to_bytes() {
        if at >= line.len() - tail.len() - 1 {
            break;
        }
        line[at] = byte;
        at += 1;
    }
    line[at..at + tail.len()].copy_from_slice(tail);
    at += tail.len();
    unsafe {
        crate::patina_stdio_write(2, line.as_ptr().cast(), at);
    }
    crate::patina_abort()
}
#[cfg(target_os = "linux")]
pub(crate) fn chk_fail() -> ! {
    fortify_fail(c"buffer overflow detected")
}

#[cfg(target_os = "linux")]
pub(crate) fn get_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

pub(crate) fn at(directory: c_int) -> c_int {
    if directory == libc::AT_FDCWD {
        crate::paths::AT_FDCWD
    } else {
        directory
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn get_errno() -> c_int {
    unsafe { *libc::__error() }
}

#[cfg(target_os = "macos")]
pub(crate) fn deny(message: &CStr) -> c_int {
    unsafe {
        crate::patina_stdio_write(2, message.as_ptr().cast(), message.count_bytes());
    }
    error(libc::ENOSYS)
}
