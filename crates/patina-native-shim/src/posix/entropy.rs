//! Seeded entropy through the same private implementations as dynamic lookup.
#![deny(clippy::undocumented_unsafe_blocks)]
use crate::abi::{self, Errno, SysResult};
use crate::entropy::EntropyWait;
use core::ffi::{c_int, c_void};

/// `getentropy`'s libc-specific size check followed by the shared seeded fill.
///
/// `getentropy` waits for the pool and never fails on its own. glibc 2.39's
/// (`sysdeps/unix/sysv/linux/getentropy.c`) refuses more than 256 bytes with
/// `EIO`, returns 0 for an empty request without entering the kernel, and
/// otherwise calls `getrandom` with flags 0, retrying `EINTR`. Darwin's is a
/// system call (XNU `bsd/dev/random/randomdev.c`) that refuses more than 256
/// bytes with `EINVAL`, over a pool seeded before userspace runs. Its only
/// other error is the buffer's.
///
/// # Safety
/// `destination` is the caller's output buffer and follows getentropy's contract.
unsafe fn getentropy_core(destination: *mut c_void, length: usize) -> SysResult<c_int> {
    #[cfg(target_os = "linux")]
    const TOO_LONG: c_int = libc::EIO;
    #[cfg(target_os = "macos")]
    const TOO_LONG: c_int = libc::EINVAL;
    if length > 256 {
        return Err(Errno::new(TOO_LONG));
    }
    // An empty request makes no request of the pool, so it cannot show the
    // pool ready.
    if length == 0 {
        return Ok(0);
    }
    // SAFETY: the caller's getentropy buffer contract also satisfies `fill`.
    let written = unsafe { crate::entropy::fill(destination, length, EntropyWait::UntilReady) }?;
    // glibc's loop asks again past a short write and meets the fault there;
    // Darwin's `copyout` is all or nothing. Either way it is `EFAULT`.
    if written < length {
        return Err(Errno::new(libc::EFAULT));
    }
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
    // CommonCrypto documents no failure (`CommonRandom.h`: "Return kCCSuccess
    // on success"), and Rust's std asserts success. The system pool is ready
    // before the guest runs, so the entropy fault never reaches this entry.
    // SAFETY: the caller supplies CommonCrypto's output buffer.
    let filled = unsafe { crate::entropy::fill(destination, length, EntropyWait::UntilReady) };
    if filled != Ok(length) {
        // Preserve __builtin_trap's instruction fault, rather than guest abort.
        // SAFETY: this noreturn instruction intentionally raises the established trap.
        unsafe { core::arch::asm!("brk #1", options(noreturn)) }
    }
    0
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_deterministic_getentropy");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_deterministic_getentropy");
