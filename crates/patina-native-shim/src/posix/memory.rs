//! Memory adapters: the libc address-space calls over `mem`'s rows. On Linux
//! the raw failure range is distinct from pointer bits; macOS defines the
//! calls a mapping of a guest descriptor reaches (`mmap`, `munmap`,
//! `mprotect`, `msync`), and the rest stay libSystem's process-local memory.
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use core::ffi::c_char;
use core::ffi::{c_int, c_void};

#[cfg(target_os = "linux")]
fn result(value: i64) -> c_int {
    crate::abi::libc_result(crate::abi::LinuxReturn::new(value).decode().map(|_| 0), -1)
}

/// # Safety
/// Mapping ranges satisfy mmap's existing guest contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn mmap(
    hint: *mut c_void,
    length: usize,
    protection: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(
        crate::mem::mmap(hint as usize, length, protection, flags, fd, offset),
        libc::MAP_FAILED as usize,
    ) as *mut c_void
}
/// # Safety
/// Same range contract as mmap64.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
unsafe extern "C" fn mmap64(
    hint: *mut c_void,
    length: usize,
    protection: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off64_t,
) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(
        crate::mem::mmap(hint as usize, length, protection, flags, fd, offset),
        libc::MAP_FAILED as usize,
    ) as *mut c_void
}
#[unsafe(no_mangle)]
extern "C" fn munmap(address: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(crate::mem::munmap(address as usize, length).map(|_| 0), -1)
}
#[unsafe(no_mangle)]
extern "C" fn msync(address: *mut c_void, length: usize, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"msync");
    crate::abi::libc_result(
        crate::mem::msync(address as usize, length, flags).map(|_| 0),
        -1,
    )
}
#[unsafe(no_mangle)]
extern "C" fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_result(
        crate::mem::mprotect(address as usize, length, protection).map(|_| 0),
        -1,
    )
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn madvise(address: *mut c_void, length: usize, advice: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::madvise(
        address as usize,
        length,
        advice as usize,
    ))
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn mlock(address: *const c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_mlock(address as usize, length, 0))
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn mlock2(address: *const c_void, length: usize, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_mlock(address as usize, length, flags))
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn munlock(address: *const c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_munlock(address as usize, length))
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn mlockall(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_mlockall(flags))
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn munlockall() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    result(crate::mem::patina_munlockall())
}
/// # Safety
/// name is a guest C string, imported by the model through uaccess.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
unsafe extern "C" fn memfd_create(name: *const c_char, flags: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::model_result({
        // SAFETY: this export's contract guarantees the bounded name scan can read through NUL.
        unsafe { crate::mem::patina_memfd_create(name, flags) }
    })
}
