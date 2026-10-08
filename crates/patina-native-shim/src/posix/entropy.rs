//! Seeded entropy through the same private implementations as dynamic lookup.
#![deny(clippy::undocumented_unsafe_blocks)]
use crate::abi::{self, Errno, SysResult};
use core::ffi::{c_int, c_void};

/// `getentropy`'s libc-specific size check followed by the shared seeded fill.
///
/// # Safety
/// `destination` is the caller's output buffer and follows getentropy's contract.
unsafe fn getentropy_core(destination: *mut c_void, length: usize) -> SysResult<c_int> {
    if length > 256 {
        return Err(Errno::new(libc::EIO));
    }
    // SAFETY: the caller's getentropy buffer contract also satisfies `fill`.
    unsafe { crate::entropy::fill(destination, length) }?;
    Ok(0)
}

/// # Safety
/// The destination is guest memory, copied by the entropy model's uaccess.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn patina_deterministic_getentropy(
    destination: *mut c_void,
    length: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this export has the same output-buffer contract as getentropy.
    abi::libc_result(unsafe { getentropy_core(destination, length) }, -1)
}

/// # Safety
/// The destination is guest memory, copied by the getrandom model's uaccess.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn patina_deterministic_getrandom(
    destination: *mut c_void,
    length: usize,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this export has the same output-buffer contract as getrandom.
    abi::libc_result(
        unsafe { crate::entropy::getrandom(destination, length, flags) },
        -1,
    )
}

/// # Safety
/// Same guest buffer contract as getentropy.
#[unsafe(no_mangle)]
unsafe extern "C" fn getentropy(destination: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller supplies getentropy's output buffer.
    abi::libc_result(unsafe { getentropy_core(destination, length) }, -1)
}

#[cfg(target_os = "linux")]
/// # Safety
/// Same guest buffer contract as getrandom.
#[unsafe(no_mangle)]
unsafe extern "C" fn getrandom(destination: *mut c_void, length: usize, flags: u32) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"getrandom");
    // SAFETY: the caller supplies getrandom's output buffer.
    abi::libc_result(
        unsafe { crate::entropy::getrandom(destination, length, flags) },
        -1,
    )
}

#[cfg(target_os = "macos")]
/// # Safety
/// Same guest buffer contract as the CommonCrypto entropy entry.
#[unsafe(no_mangle)]
unsafe extern "C" fn CCRandomGenerateBytes(destination: *mut c_void, length: usize) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller supplies CommonCrypto's output buffer.
    if unsafe { crate::entropy::fill(destination, length) }.is_err() {
        // Preserve __builtin_trap's instruction fault, rather than guest abort.
        // SAFETY: this noreturn instruction intentionally raises the established trap.
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
