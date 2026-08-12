//! Timestamp-counter trap — `rdtsc` / `rdtscp`, x86-64 Linux only.
//!
//! The C layer (`patina_posix.c`) arms `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` at
//! init and installs a `SIGSEGV` handler. With the TSC disabled for the thread,
//! the CPU raises `#GP` on `rdtsc`/`rdtscp`, which the kernel delivers as a
//! synchronous, thread-directed `SIGSEGV` at the exact faulting instruction. The
//! C handler validates that the faulting `RIP` lies in the main executable's
//! text, then calls [`patina_tsc_dispatch`], which decodes the instruction and —
//! for the two counter reads — returns the value the handler writes into
//! `EDX:EAX` (plus `IA32_TSC_AUX` in `ECX` for `rdtscp`) before stepping `RIP`
//! past the instruction. Anything else the handler leaves alone: a genuine
//! segmentation fault is never swallowed.
//!
//! **Interposer parity.** The counter is not a second clock. It is the run's
//! virtual monotonic clock read through the SAME `patina_clock_now` entry point
//! every C interposer and SUD row uses, so an `rdtsc` and a `clock_gettime`
//! record the identical `ClockNow` operation and replay from the identical
//! recorded value. Determinism is therefore by construction, not by a parallel
//! model that could drift.
//!
//! **Frequency mapping.** One tick is one virtual nanosecond — a nominal 1 GHz
//! invariant TSC. That choice makes the counter *self-consistent with the clock
//! a guest calibrates it against*: a guest that measures `rdtsc` deltas across a
//! `clock_gettime` interval derives exactly 1 GHz, every time, on every host.
//! The counter starts at 0 (the virtual clock's origin) rather than at a host
//! boot value.
//!
//! **Monotonicity.** Exactly the virtual clock's: non-decreasing, and advancing
//! only when the runtime advances time (a sleep, a modeled latency). Two reads
//! with nothing between them return the SAME tick, precisely as two
//! `clock_gettime` calls do. This is parity, not an approximation of it — a
//! guest spin-waiting on `rdtsc` deltas without yielding hangs exactly as one
//! spinning on `Instant::now` deltas does.
//!
//! This module is x86-64-only (`PR_SET_TSC` is an x86 facility). arm64's
//! `mrs CNTVCT_EL0` has no equivalent trap and stays a refusal — see
//! `native_escape_is_tsc_manageable` in `patina-target`.

use std::cell::Cell;
use std::ffi::{c_int, c_uint};

unsafe extern "C" {
    fn patina_clock_now(clock: u32, nanos: *mut u64) -> c_int;
}

/// Patina clock id for the monotonic domain (see `patina_native.h`).
const PATINA_CLOCK_MONOTONIC: u32 = 1;

/// Dispatch outcomes, shared with the C handler (`patina_native.h`).
/// Not a counter read: the handler must fall through to the fatal path.
pub const PATINA_TSC_NONE: c_int = 0;
/// `rdtsc` (`0f 31`): two bytes, writes `EDX:EAX`.
pub const PATINA_TSC_RDTSC: c_int = 1;
/// `rdtscp` (`0f 01 f9`): three bytes, writes `EDX:EAX` and `ECX`.
pub const PATINA_TSC_RDTSCP: c_int = 2;

/// The deterministic `IA32_TSC_AUX` value `rdtscp` reports in `ECX`. Linux packs
/// `(numa_node << 12) | cpu_id` there, and it is what `sched_getcpu()` reads on a
/// vDSO-less path — so it must agree with the rest of the simulation's single-CPU
/// model: cpu 0, node 0. A host value here would leak the scheduler's real core
/// placement into the guest.
const PATINA_TSC_AUX: c_uint = 0;

thread_local! {
    /// Set while this thread is inside [`patina_tsc_dispatch`]. A nested trap —
    /// a counter read taken *while servicing a counter read* — can only mean
    /// shim/runtime code executed `rdtsc` itself, which the audit instruction
    /// scan proves it does not. Without the guard that would be an unbounded
    /// SIGSEGV storm; with it, it is one loud, named abort. This is the
    /// standalone RED detector for the containment invariant, mirroring the SUD
    /// dispatch guard.
    static IN_DISPATCH: Cell<bool> = const { Cell::new(false) };
}

/// Classify the instruction at the start of `bytes` as a timestamp-counter read,
/// returning `(kind, instruction length)`.
///
/// This is deliberately an exact-encoding test, not a prefix-tolerant decode:
/// the two counter instructions take no prefixes in any encoding a compiler
/// emits, and the trap must never step `RIP` past something it did not fully
/// recognize. Anything unrecognized returns `None`, and the caller fails closed
/// onto the ordinary fault path.
fn classify(bytes: &[u8]) -> Option<(c_int, usize)> {
    match bytes {
        // rdtsc: 0f 31.
        [0x0f, 0x31, ..] => Some((PATINA_TSC_RDTSC, 2)),
        // rdtscp: 0f 01 f9 (group 7, mod=3 reg=7 rm=1).
        [0x0f, 0x01, 0xf9, ..] => Some((PATINA_TSC_RDTSCP, 3)),
        _ => None,
    }
}

/// Read the virtual monotonic clock as a counter tick (1 tick = 1 ns; see the
/// module docs). Returns `None` when the clock entry point fails, which the
/// caller turns into a fatal abort rather than a fabricated value.
fn counter_now() -> Option<u64> {
    let mut nanos: u64 = 0;
    // SAFETY: `nanos` is local, writable storage; this is the same entry point
    // every C interposer calls for a clock read.
    let rc = unsafe { patina_clock_now(PATINA_CLOCK_MONOTONIC, &mut nanos) };
    (rc == 0).then_some(nanos)
}

/// The SIGSEGV timestamp-counter dispatch entry point. The C handler passes the
/// bytes at the faulting `RIP` (already validated to lie in the main
/// executable's text) and out-parameters for the counter value, the `rdtscp`
/// auxiliary value, and the instruction length.
///
/// Returns [`PATINA_TSC_NONE`] when the faulting instruction is not a counter
/// read — the handler must then take the ordinary fault path, because the
/// SIGSEGV is a genuine one. On a counter read it returns the kind and fills the
/// out-parameters; the handler writes the registers and steps `RIP` by `length`.
///
/// The exported name doubles as the audit's trap marker: a binary whose symbol
/// table *defines* `patina_tsc_dispatch` carries a trap-capable shim, which is
/// condition (a) of the `rdtsc`/`rdtscp` audit downgrade (see `patina-target`).
///
/// # Safety
/// Called only from the C `SIGSEGV` handler on the faulting thread, with
/// `bytes`/`available` describing readable executable memory and the three
/// out-pointers pointing at the handler's own stack storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_tsc_dispatch(
    bytes: *const u8,
    available: usize,
    tsc_out: *mut u64,
    aux_out: *mut c_uint,
    length_out: *mut usize,
) -> c_int {
    if bytes.is_null() || available == 0 {
        return PATINA_TSC_NONE;
    }
    // SAFETY: the C handler proved `bytes..bytes+available` is inside the main
    // executable's mapped text.
    let window = unsafe { std::slice::from_raw_parts(bytes, available) };
    // `classify` matches the whole encoding against the window it was given, so a
    // window truncated by the end of the text mapping cannot yield an instruction
    // longer than it — the trap never steps RIP over bytes that are not there.
    let Some((kind, length)) = classify(window) else {
        return PATINA_TSC_NONE;
    };
    if IN_DISPATCH.with(Cell::get) {
        crate::trap_fatal(
            "TSC: re-entered the timestamp-counter trap while servicing one: shim/runtime code \
             executed rdtsc/rdtscp inside the SIGSEGV handler (the instruction scan proves this \
             cannot happen — a reentry means the containment invariant is broken)",
        );
    }
    IN_DISPATCH.with(|cell| cell.set(true));
    let value = counter_now();
    IN_DISPATCH.with(|cell| cell.set(false));
    let Some(value) = value else {
        crate::trap_fatal(
            "TSC: the virtual clock refused a timestamp-counter read; refusing to fabricate a \
             counter value for rdtsc/rdtscp",
        );
    };
    // SAFETY: the three out-pointers are the handler's own stack storage.
    unsafe {
        tsc_out.write(value);
        aux_out.write(PATINA_TSC_AUX);
        length_out.write(length);
    }
    kind
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_exactly_the_two_counter_reads() {
        assert_eq!(classify(&[0x0f, 0x31]), Some((PATINA_TSC_RDTSC, 2)));
        assert_eq!(classify(&[0x0f, 0x01, 0xf9]), Some((PATINA_TSC_RDTSCP, 3)));
        // Trailing bytes are ignored: the window is whatever text follows.
        assert_eq!(
            classify(&[0x0f, 0x31, 0x48, 0x89, 0xc1]),
            Some((PATINA_TSC_RDTSC, 2))
        );
    }

    #[test]
    fn refuses_everything_else_so_real_faults_are_not_swallowed() {
        // The neighbours that share a prefix with the counter reads: `swapgs`
        // (0f 01 f8) and the group-7 memory forms, `rdpmc` (0f 33), `cpuid`
        // (0f a2), `syscall` (0f 05) — plus an ordinary load and a truncated
        // `0f`. Each must fall through, or the handler would step RIP past an
        // instruction it did not execute and corrupt the guest.
        for bytes in [
            &[0x0f, 0x01, 0xf8][..],
            &[0x0f, 0x01, 0x00][..],
            &[0x0f, 0x33][..],
            &[0x0f, 0xa2][..],
            &[0x0f, 0x05][..],
            &[0x48, 0x8b, 0x00][..],
            &[0x0f][..],
            &[][..],
        ] {
            assert_eq!(classify(bytes), None, "must not claim {bytes:02x?}");
        }
    }

    #[test]
    fn a_prefixed_encoding_is_not_claimed() {
        // `f3 0f 31` is not an encoding any compiler emits, and stepping RIP by
        // 2 from the prefix byte would land mid-instruction. Fail closed.
        assert_eq!(classify(&[0xf3, 0x0f, 0x31]), None);
        assert_eq!(classify(&[0x66, 0x0f, 0x01, 0xf9]), None);
    }

    #[test]
    fn dispatch_declines_a_truncated_window() {
        // A window too short to hold the decoded instruction (the last two bytes
        // of a text mapping being `0f 01`) must not be claimed.
        let bytes = [0x0f, 0x01, 0xf9];
        let mut tsc = 0u64;
        let mut aux = 0u32;
        let mut length = 0usize;
        // SAFETY: valid pointers into local storage.
        let kind =
            unsafe { patina_tsc_dispatch(bytes.as_ptr(), 2, &mut tsc, &mut aux, &mut length) };
        assert_eq!(kind, PATINA_TSC_NONE);
        // A null/empty window likewise.
        // SAFETY: as above.
        let kind =
            unsafe { patina_tsc_dispatch(std::ptr::null(), 3, &mut tsc, &mut aux, &mut length) };
        assert_eq!(kind, PATINA_TSC_NONE);
    }
}
