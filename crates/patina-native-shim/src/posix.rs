//! Guest-only ordinary POSIX adapters. Host dependency builds omit this module.
use core::ffi::CStr;
use core::ffi::c_int;

#[cfg(target_os = "macos")]
mod darwin;
mod dlsym;
#[cfg(target_os = "linux")]
mod door_thunks;
mod entropy;
mod fd_io;
mod fs;
mod lifecycle;
#[cfg(target_os = "linux")]
mod memory;
mod net;
mod privileged;
mod readiness;
mod sched_identity;
mod signal_process;
pub(crate) mod stdio;
mod thread_sync;
mod time;
mod timers;

pub(crate) use crate::variadic::{error, model_result};

pub(crate) fn size_result(result: isize) -> isize {
    crate::abi::libc_result(crate::abi::from_model(result), result)
}

pub(crate) fn cancel(name: &CStr) {
    #[cfg(target_os = "linux")]
    unsafe {
        crate::thread::cancel::patina_cancel_point(name.as_ptr());
    }
    #[cfg(target_os = "macos")]
    let _ = name;
}

/// A raw model result as libc's: pending signals delivered before errno.
#[cfg(target_os = "linux")]
pub(crate) fn signal_result(result: i64) -> c_int {
    crate::abi::libc_delivered(crate::abi::from_neg(result), -1) as c_int
}

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

// zstd's static library references these weak tracing hooks (Linux corpus
// only; the macOS zstd build config does not surface them). A begin() that
// answers 0 disables tracing (zstd_trace.h), so these no-op strong
// definitions satisfy the weak references and keep the names off the import
// table. C linkage does not encode argument types: opaque pointers bind.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_trace_compress_begin(_cctx: *const core::ffi::c_void) -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_trace_compress_end(_ctx: u64, _trace: *const core::ffi::c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_trace_decompress_begin(_dctx: *const core::ffi::c_void) -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_trace_decompress_end(_ctx: u64, _trace: *const core::ffi::c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}
