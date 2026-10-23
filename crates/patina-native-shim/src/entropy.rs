//! Deterministic entropy and getrandom entry points.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::abi::{SysResult, failed};
pub(crate) use patina_dst_runtime::EntropyWait;

/// The most one seeded draw holds: a request is drawn and copied this much at
/// a time, so a request's size bounds neither the shim's memory nor a bad
/// destination's cost. The seeded stream is chunk-independent, so the bytes are
/// those of one draw.
const ENTROPY_CHUNK: usize = 64 * 1024;

/// The granularity at which a guest range can fault: the modeled page, which
/// divides every host page size.
const FAULT_GRANULE: usize = 4096;

/// Fill caller-owned memory from the seeded stream, for an entry point that
/// meets an uninitialized random pool as `wait` says, and answer how many bytes
/// reached it. Only [`EntropyWait::FailIfUnready`] can be handed the entropy
/// fault.
///
/// This is 6.8's `getrandom` shape (`drivers/char/random.c`): the pool is
/// consulted before the buffer, since readiness comes before `import_ubuf`;
/// then the bytes are generated and copied a block at a time
/// (`get_random_bytes_user`), and a copy that faults ends the request with the
/// bytes already written, or `EFAULT` when there are none. Each
/// [`ENTROPY_CHUNK`] is one recorded draw, the first carrying the readiness
/// decision. A draw's chunks depend only on the request's length and on where
/// the destination stops being writable, so a replay draws the same sequence.
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
pub(crate) unsafe fn fill(
    destination: *mut c_void,
    length: usize,
    wait: EntropyWait,
) -> SysResult<usize> {
    let start = destination as usize;
    let mut written = 0;
    loop {
        let chunk = (length - written).min(ENTROPY_CHUNK);
        #[expect(
            clippy::disallowed_methods,
            reason = "the guest's own entropy request (getrandom, getentropy, a /dev/urandom read)"
        )]
        let bytes = with_context(|context| context.entropy_bytes(chunk, wait)).map_err(failed)?;
        let landed = write_prefix(start.wrapping_add(written), &bytes);
        written += landed;
        if landed < chunk {
            break;
        }
        if written == length {
            set_errno(0);
            return Ok(written);
        }
    }
    if written == 0 {
        return Err(failed(EFAULT));
    }
    set_errno(0);
    Ok(written)
}

/// Copy `bytes` to the guest at `address` and answer how many landed: all of
/// them, or, when the range faults, the ones before the first granule that
/// could not be written.
fn write_prefix(address: usize, bytes: &[u8]) -> usize {
    if uaccess::write_bytes(address, bytes).is_ok() {
        return bytes.len();
    }
    let mut landed = 0;
    while landed < bytes.len() {
        let at = address.wrapping_add(landed);
        let granule = (FAULT_GRANULE - at % FAULT_GRANULE).min(bytes.len() - landed);
        if uaccess::write_bytes(at, &bytes[landed..landed + granule]).is_err() {
            break;
        }
        landed += granule;
    }
    landed
}

/// `getrandom(2)` over the seeded stream: the bytes written, which a buffer
/// that stops being writable partway through makes fewer than asked.
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn getrandom(
    destination: *mut c_void,
    length: usize,
    flags: u32,
) -> SysResult<isize> {
    if !getrandom_flags_accepted(flags) {
        return Err(failed(EINVAL));
    }
    // An empty request still meets the pool: the kernel's readiness check
    // comes before the length matters.
    let length = length.min(MAX_RW_COUNT);
    // SAFETY: this function has the same destination contract as `fill`.
    let written = unsafe { fill(destination, length, getrandom_wait(flags)) }?;
    Ok(written as isize)
}

/// How `getrandom(2)` with `flags` meets a pool that is not yet initialized,
/// in 6.8's order (`SYSCALL_DEFINE3(getrandom)`): `GRND_INSECURE` reads
/// regardless, then `GRND_NONBLOCK` answers `EAGAIN`, and otherwise the call
/// waits for the pool. `GRND_RANDOM` changes none of this since 5.6, when the
/// blocking pool was removed.
#[cfg(target_os = "linux")]
fn getrandom_wait(flags: u32) -> EntropyWait {
    use linux_raw_sys::general::{GRND_INSECURE, GRND_NONBLOCK};
    if flags & GRND_INSECURE != 0 {
        EntropyWait::Never
    } else if flags & GRND_NONBLOCK != 0 {
        EntropyWait::FailIfUnready
    } else {
        EntropyWait::UntilReady
    }
}

#[unsafe(no_mangle)]
/// Fill caller-owned memory with deterministic bytes, as a `/dev/urandom` read
/// does: 0 when every byte landed, or -1. Such a read never waits for the pool
/// (`urandom_read_iter`), so the entropy fault never fails it.
///
/// # Safety
/// `destination` is a guest address; it is written only through `uaccess`.
pub unsafe extern "C" fn patina_entropy(destination: *mut c_void, length: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this export carries the guest-buffer contract documented above.
    match unsafe { fill(destination, length, EntropyWait::Never) } {
        Ok(written) if written == length => 0,
        Ok(_) => {
            set_errno(EFAULT);
            -1
        }
        Err(_) => -1,
    }
}

/// Does the kernel's `getrandom(2)` accept `flags`? Every bit outside
/// `GRND_NONBLOCK|GRND_RANDOM|GRND_INSECURE`, and `GRND_INSECURE` with
/// `GRND_RANDOM`, is `EINVAL` (`drivers/char/random.c`).
#[cfg(target_os = "linux")]
pub(crate) fn getrandom_flags_accepted(flags: u32) -> bool {
    use linux_raw_sys::general::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM};
    let insecure_random = GRND_INSECURE | GRND_RANDOM;
    flags & !(GRND_NONBLOCK | insecure_random) == 0 && flags & insecure_random != insecure_random
}

/// The most one read-like call transfers: `MAX_RW_COUNT`, `INT_MAX` rounded
/// down to the modeled 4096-byte page.
#[cfg(target_os = "linux")]
const MAX_RW_COUNT: usize = i32::MAX as usize & !4095;
