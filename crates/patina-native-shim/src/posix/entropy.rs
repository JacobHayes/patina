//! Seeded entropy through the same private implementations as dynamic lookup.
use core::ffi::{c_int, c_void};

/// # Safety
/// The destination is guest memory, copied by the entropy model's uaccess.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_deterministic_getentropy(
    destination: *mut c_void,
    length: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length > 256 {
        return super::error(libc::EIO);
    }
    super::model_result(unsafe { crate::patina_entropy(destination, length) })
}

/// # Safety
/// The destination is guest memory, copied by the getrandom model's uaccess.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_deterministic_getrandom(
    destination: *mut c_void,
    length: usize,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::size_result(unsafe { crate::patina_getrandom(destination, length, flags) })
}

/// # Safety
/// Same guest buffer contract as getentropy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getentropy(destination: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { patina_deterministic_getentropy(destination, length) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Same guest buffer contract as getrandom.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrandom(destination: *mut c_void, length: usize, flags: u32) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"getrandom");
    unsafe { patina_deterministic_getrandom(destination, length, flags) }
}

#[cfg(target_os = "macos")]
/// # Safety
/// Same guest buffer contract as the CommonCrypto entropy entry.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CCRandomGenerateBytes(destination: *mut c_void, length: usize) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if unsafe { crate::patina_entropy(destination, length) } != 0 {
        // Preserve __builtin_trap's instruction fault, rather than guest abort.
        unsafe { core::arch::asm!("brk #1", options(noreturn)) }
    }
    0
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".hidden patina_deterministic_getentropy",
    ".hidden patina_deterministic_getrandom"
);
#[cfg(target_os = "macos")]
core::arch::global_asm!(
    ".private_extern _patina_deterministic_getentropy",
    ".private_extern _patina_deterministic_getrandom"
);
