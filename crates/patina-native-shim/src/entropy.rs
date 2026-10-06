//! Deterministic entropy and getrandom entry points.

use super::*;

#[unsafe(no_mangle)]
/// Fill caller-owned memory with deterministic bytes: 0, or -1 with `EFAULT`
/// for a buffer the guest cannot write (the bytes are drawn either way,
/// except for a NULL buffer).
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
pub unsafe extern "C" fn patina_entropy(destination: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if length != 0 && destination.is_null() {
        return fail(EFAULT);
    }
    let result = with_context(|context| context.entropy_bytes(length));
    match result {
        // Copied as the kernel's `copy_to_user` copies: a buffer the guest
        // cannot write is `EFAULT`, never a fault in shim code.
        Ok(bytes) => match uaccess::write_bytes(destination as usize, &bytes) {
            Ok(()) => {
                set_errno(0);
                0
            }
            Err(errno) => fail(errno),
        },
        Err(errno) => fail(errno),
    }
}

/// Does the kernel's `getrandom(2)` accept `flags`? Every bit outside
/// `GRND_NONBLOCK|GRND_RANDOM|GRND_INSECURE`, and `GRND_INSECURE` with
/// `GRND_RANDOM`, is `EINVAL` (`drivers/char/random.c`).
pub(crate) fn getrandom_flags_accepted(flags: u32) -> bool {
    use linux_raw_sys::general::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM};
    let insecure_random = GRND_INSECURE | GRND_RANDOM;
    flags & !(GRND_NONBLOCK | insecure_random) == 0 && flags & insecure_random != insecure_random
}

/// The most one read-like call transfers: `MAX_RW_COUNT`, `INT_MAX` rounded
/// down to the modeled 4096-byte page.
const MAX_RW_COUNT: usize = i32::MAX as usize & !4095;

#[unsafe(no_mangle)]
/// `getrandom(2)` over the seeded stream: the byte count, -1/`EINVAL` for a
/// flag word the kernel refuses, or -1/`EFAULT` for a null buffer. The stream
/// never blocks and has one pool, so the accepted flags change nothing. One
/// draw is at most `MAX_RW_COUNT` bytes, as on the kernel. The C `getrandom`
/// and the SUD row both answer here.
///
/// # Safety
/// `destination` must be writable for `length` bytes when `length` is nonzero.
pub unsafe extern "C" fn patina_getrandom(
    destination: *mut c_void,
    length: usize,
    flags: u32,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !getrandom_flags_accepted(flags) {
        return fail(EINVAL) as isize;
    }
    if length != 0 && destination.is_null() {
        return fail(EFAULT) as isize;
    }
    let length = length.min(MAX_RW_COUNT);
    // SAFETY: Guaranteed by this function's C ABI contract.
    match unsafe { patina_entropy(destination, length) } {
        0 => length as isize,
        _ => -1,
    }
}
