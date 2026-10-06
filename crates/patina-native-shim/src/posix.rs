//! Guest-only ordinary POSIX adapters. Host dependency builds omit this module.
use core::ffi::CStr;
use core::ffi::c_int;

mod entropy;
#[cfg(target_os = "linux")]
mod memory;
mod privileged;
mod readiness;
mod sched_identity;

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

#[unsafe(no_mangle)]
pub extern "C" fn fail_int(result: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    model_result(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn fail_size(result: isize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    size_result(result)
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden fail_int", ".hidden fail_size");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _fail_int", ".private_extern _fail_size");

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
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
core::arch::global_asm!(".hidden signal_result");

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
/// # Safety
/// message points to a terminated C diagnostic string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_fortify_fail(message: *const core::ffi::c_char) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    fortify_fail(unsafe { CStr::from_ptr(message) })
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_chk_fail() -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    chk_fail()
}
#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_fortify_fail", ".hidden patina_chk_fail");
