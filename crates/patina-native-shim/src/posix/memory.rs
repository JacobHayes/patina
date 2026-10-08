//! Linux memory adapters: the raw failure range is distinct from pointer bits.
use core::ffi::{c_char, c_int, c_void};

fn failed(result: i64) -> bool {
    crate::abi::libc_result(
        crate::abi::LinuxReturn::new(result).decode().map(|_| false),
        true,
    )
}
fn address(result: i64) -> *mut c_void {
    if failed(result) {
        libc::MAP_FAILED
    } else {
        result as usize as *mut c_void
    }
}
fn result(value: i64) -> c_int {
    if failed(value) { -1 } else { 0 }
}

/// # Safety
/// Mapping ranges satisfy mmap's existing guest contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(
    hint: *mut c_void,
    length: usize,
    protection: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    address(crate::mem::patina_mmap(
        hint as usize,
        length,
        protection,
        flags,
        fd,
        offset,
    ))
}
/// # Safety
/// Same range contract as mmap64.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap64(
    hint: *mut c_void,
    length: usize,
    protection: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off64_t,
) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    address(crate::mem::patina_mmap(
        hint as usize,
        length,
        protection,
        flags,
        fd,
        offset,
    ))
}
#[unsafe(no_mangle)]
pub extern "C" fn munmap(address: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_munmap(address as usize, length))
}
#[unsafe(no_mangle)]
pub extern "C" fn msync(address: *mut c_void, length: usize, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"msync");
    result(crate::mem::patina_msync(address as usize, length, flags))
}
#[unsafe(no_mangle)]
pub extern "C" fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_mprotect(
        address as usize,
        length,
        protection,
    ))
}
#[unsafe(no_mangle)]
pub extern "C" fn mlock(address: *const c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_mlock(address as usize, length, 0))
}
#[unsafe(no_mangle)]
pub extern "C" fn mlock2(address: *const c_void, length: usize, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_mlock(address as usize, length, flags))
}
#[unsafe(no_mangle)]
pub extern "C" fn munlock(address: *const c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_munlock(address as usize, length))
}
#[unsafe(no_mangle)]
pub extern "C" fn mlockall(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_mlockall(flags))
}
#[unsafe(no_mangle)]
pub extern "C" fn munlockall() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_munlockall())
}
/// # Safety
/// name is a guest C string, imported by the model through uaccess.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::model_result(unsafe { crate::mem::patina_memfd_create(name, flags) })
}
