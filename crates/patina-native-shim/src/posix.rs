//! Guest-only ordinary POSIX adapters. Host dependency builds omit this module.
#[cfg(target_os = "linux")]
use core::ffi::CStr;
use core::ffi::c_int;

mod entropy;

pub(crate) use crate::variadic::{error, model_result};

pub(crate) fn size_result(result: isize) -> isize {
    if result < 0 {
        error(crate::patina_errno());
    }
    result
}

#[cfg(target_os = "linux")]
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
