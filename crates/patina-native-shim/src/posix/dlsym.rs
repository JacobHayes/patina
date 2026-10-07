//! Dynamic lookup is registry-only, whatever the guest's dl handle.
use core::ffi::{CStr, c_char, c_void};
use core::ptr;
#[cfg(target_os = "linux")]
mod linux;

/// # Safety
/// symbol is null or a readable NUL-terminated name.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_dlsym_route(symbol: *const c_char) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if symbol.is_null() {
        return ptr::null_mut();
    }
    let name = unsafe { CStr::from_ptr(symbol) };
    #[cfg(target_os = "linux")]
    {
        linux::route(name)
    }
    #[cfg(target_os = "macos")]
    {
        match name.to_bytes() {
            b"getentropy" => {
                super::entropy::patina_deterministic_getentropy as *const () as *mut c_void
            }
            b"getrandom" => {
                super::entropy::patina_deterministic_getrandom as *const () as *mut c_void
            }
            _ => ptr::null_mut(),
        }
    }
}
