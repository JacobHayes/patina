//! Single-use, per-thread dlerror diagnostic, retaining glibc's shape.
use super::*;
use core::cell::{Cell, UnsafeCell};
thread_local! {
    static MESSAGE: UnsafeCell<[c_char; 512]> = const { UnsafeCell::new([0; 512]) };
    static PENDING: Cell<bool> = const { Cell::new(false) };
}
// Generated from existing registry rows. Entries are opaque hidden addresses;
// no alias is ever called through a fabricated function signature.
include!(concat!(env!("OUT_DIR"), "/dlsym_routes.rs"));

unsafe fn set_error(symbol: *const c_char) {
    unsafe {
        let program = super::super::lifecycle::program_path();
        let program = if program.is_null() {
            c""
        } else {
            CStr::from_ptr(program)
        };
        let name = if symbol.is_null() {
            c"(null)"
        } else {
            CStr::from_ptr(symbol)
        };
        MESSAGE.with(|message| {
            let bytes = message.get().cast::<u8>();
            let mut at = 0;
            for part in [
                program.to_bytes(),
                b": undefined symbol: ",
                name.to_bytes(),
                b" (patina: dynamic lookup answers only the names the shim defines)",
            ] {
                let length = part.len().min(511 - at);
                ptr::copy_nonoverlapping(part.as_ptr(), bytes.add(at), length);
                at += length;
            }
            bytes.add(at).write(0);
        });
    }
}
/// # Safety
/// symbol is null or a readable NUL-terminated name.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_dlsym(_handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let entry = unsafe { super::patina_dlsym_route(symbol) };
    PENDING.with(|pending| pending.set(entry.is_null()));
    if entry.is_null() {
        unsafe {
            set_error(symbol);
        }
    }
    entry
}
#[unsafe(no_mangle)]
pub extern "C" fn dlerror() -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !PENDING.with(|pending| pending.replace(false)) {
        return ptr::null_mut();
    }
    MESSAGE.with(|message| message.get().cast())
}
core::arch::global_asm!(
    ".globl patina_route_dlsym",
    ".hidden patina_route_dlsym",
    ".set patina_route_dlsym, __wrap_dlsym",
    ".globl patina_route_dlerror",
    ".hidden patina_route_dlerror",
    ".set patina_route_dlerror, dlerror",
);
