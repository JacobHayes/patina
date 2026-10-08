//! Linux mremap has a fifth argument only for explicit fixed placement.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_int, c_void};

/// # Safety
/// Mapping ranges obey mremap's contract; FIXED supplies a pointer argument.
#[unsafe(no_mangle)]
unsafe extern "C" fn mremap(
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
        // SAFETY: the armed variadic acceptance caller supplies a second
        // pointer sentinel for this mutation path.
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
