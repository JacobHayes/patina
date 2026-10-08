//! Deterministic entropy and getrandom entry points.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::abi::{SysResult, failed};

/// Fill caller-owned memory from the seeded stream.
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
pub(crate) unsafe fn fill(destination: *mut c_void, length: usize) -> SysResult<()> {
    if length != 0 && destination.is_null() {
        return Err(failed(EFAULT));
    }
    let result = with_context(|context| context.entropy_bytes(length));
    match result {
        Ok(bytes) => match uaccess::write_bytes(destination as usize, &bytes) {
            Ok(()) => {
                set_errno(0);
                Ok(())
            }
            Err(errno) => Err(failed(errno)),
        },
        Err(errno) => Err(failed(errno)),
    }
}

/// `getrandom(2)` over the seeded stream.
///
/// # Safety
/// `destination` must be writable for `length` bytes when it is nonzero.
pub(crate) unsafe fn getrandom(
    destination: *mut c_void,
    length: usize,
    flags: u32,
) -> SysResult<isize> {
    if !getrandom_flags_accepted(flags) {
        return Err(failed(EINVAL));
    }
    if length != 0 && destination.is_null() {
        return Err(failed(EFAULT));
    }
    let length = length.min(MAX_RW_COUNT);
    // SAFETY: this function has the same destination contract as `fill`.
    unsafe { fill(destination, length) }?;
    Ok(length as isize)
}

#[unsafe(no_mangle)]
/// Fill caller-owned memory with deterministic bytes: 0, or -1 on failure.
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
pub unsafe extern "C" fn patina_entropy(destination: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this export carries the guest-buffer contract documented above.
    match unsafe { fill(destination, length) } {
        Ok(()) => 0,
        Err(_) => -1,
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
    // SAFETY: this export carries getrandom's documented guest-buffer contract.
    unsafe { getrandom(destination, length, flags) }.unwrap_or(-1)
}
