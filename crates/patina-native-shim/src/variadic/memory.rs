//! Linux mremap has a fifth argument only for explicit fixed placement.
use core::ffi::{c_int, c_void};

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_mremap",
    ".hidden patina_route_mremap",
    ".set patina_route_mremap, mremap",
);

/// # Safety
/// Mapping ranges obey mremap's contract; FIXED supplies a pointer argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mremap(
    address: *mut c_void,
    old_length: usize,
    new_length: usize,
    flags: c_int,
    mut args: ...
) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mutated = super::fault(2);
    let mut destination = core::ptr::null_mut();
    if flags & libc::MREMAP_FIXED != 0 {
        // SAFETY: FIXED is the only command that supplies a destination.
        destination = unsafe { args.next_arg::<*mut c_void>() };
    }
    if mutated {
        // The armed acceptance caller supplies a second pointer sentinel.
        destination = unsafe { args.next_arg::<*mut c_void>() };
    }
    super::raw_result(crate::mem::patina_mremap(
        address as usize,
        old_length,
        new_length,
        flags as u32 as usize,
        destination as usize,
    )) as usize as *mut c_void
}
