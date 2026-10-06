//! Clock, sleep, and process CPU-time ABI entry points.

use super::*;

/// Write a deterministic clock value to caller-owned memory.
///
/// # Safety
/// `nanos` must point to writable `uint64_t` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_clock_now(clock_id: u32, nanos: *mut u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if nanos.is_null() {
        return fail(EINVAL);
    }
    let clock = match clock(clock_id) {
        Ok(clock) => clock,
        Err(errno) => return fail(errno),
    };
    // Bootstrap window (see `SHIM_BOOTSTRAP`): an allocator's constructor may
    // read time before runtime installation. Use the default clock origins so
    // default installation does not jump from zero to hours of uptime.
    // Do not enter `with_context`/`ensure_runtime`: that could re-enter the
    // allocator during its own initialization. Configured origins apply only
    // after installation; bootstrap must remain allocation- and lock-free.
    if in_shim_bootstrap() {
        let value = match clock {
            ClockKind::Monotonic => patina_dst_abi::DEFAULT_BOOT_ORIGIN_NANOS,
            ClockKind::Realtime => {
                patina_dst_abi::DEFAULT_REALTIME_EPOCH_NANOS
                    + patina_dst_abi::DEFAULT_BOOT_ORIGIN_NANOS
            }
        };
        // SAFETY: `nanos` was checked non-null and is writable per the C ABI.
        unsafe { nanos.write(value) };
        set_errno(0);
        return 0;
    }
    match with_context(|context| context.now(clock)) {
        Ok(value) => {
            // SAFETY: The pointer was checked and is required to be writable.
            unsafe { nanos.write(value) };
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_sleep_until(clock_id: u32, deadline_nanos: u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: null means no remaining-time output.
    unsafe { patina_sleep_until_remaining(clock_id, deadline_nanos, std::ptr::null_mut()) }
}

/// Sleep with an optional two-i64 kernel timespec remaining-time output.
/// Absolute sleeps pass null, so their caller's rem buffer is untouched.
/// # Safety
/// None beyond the ABI: a non-null `remaining` is copied to through
/// `uaccess` (`EFAULT` where it cannot be).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sleep_until_remaining(
    clock_id: u32,
    deadline_nanos: u64,
    remaining: *mut i64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let clock = match clock(clock_id) {
        Ok(clock) => clock,
        Err(errno) => return fail(errno),
    };
    if let Err(errno) = ensure_runtime() {
        return fail(errno);
    }
    // Apply any configured seeded sleep-latency jitter once here, at the single
    // guest-facing sleep entry, so both the managed-thread park and the
    // single-threaded clock jump below sleep to the same inflated deadline. The
    // draw is owned by the deterministic context (seeded, replayed), so the
    // jittered deadline reproduces exactly. `with_context_raw` avoids taking an
    // extra scheduling point, leaving unjittered runs byte-for-byte unchanged.
    let deadline_nanos =
        match with_context_raw(|context| Ok(context.apply_sleep_jitter(deadline_nanos))) {
            Ok(deadline) => deadline,
            Err(errno) => return fail(errno),
        };
    // With managed threads, a sleep parks on the virtual-clock timer queue so
    // other runnable tasks execute while it sleeps and the clock advances only
    // through the deadlock rescue. A single-threaded program (thread subsystem
    // never activated) keeps the direct clock jump, which is identical.
    // SAFETY: the caller supplies the optional remaining-time buffer.
    if let Some(result) = unsafe { thread::managed_sleep(clock, deadline_nanos, remaining) } {
        return if result == 0 {
            set_errno(0);
            0
        } else {
            fail(result)
        };
    }
    match with_context(|context| context.sleep_until(clock, deadline_nanos)) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// The process's virtual CPU time in nanoseconds, backing the Darwin resource
/// accounting interposers (`getrusage`/`task_info`): the modeled startup cost
/// plus what the advance-on-spin rescue charged its tasks
/// (`Context::cpu_time_nanos`; the Linux rows read it through `clocks`). Read UNRECORDED, so this read
/// emits no trace op and takes no scheduling point; the value is a pure
/// function of the recorded stream.
///
/// Always succeeds writing a value. Before the runtime is installed (a custom
/// allocator's bootstrap timing, or a binary run outside the supervisor) it
/// reports a deterministic 0 rather than auto-installing: a resource read must
/// never be the thing that forces runtime init, mirroring [`patina_clock_now`]'s
/// bootstrap leg. It does still abort when initialization has already FAILED —
/// answering 0 there would hand the guest a fabricated value for a run that was
/// refused (see [`in_shim_bootstrap`]).
///
/// # Safety
/// `nanos` must be non-null and writable for one `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cpu_time_nanos(nanos: *mut u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if nanos.is_null() {
        return fail(EINVAL);
    }
    // Bootstrap window / no runtime installed: CPU time is zero, independent
    // of the uptime origin. Never routes through `ensure_runtime`, so an
    // accounting probe cannot trip an auto-install or abort.
    let value = if in_shim_bootstrap() {
        0
    } else {
        with_context_raw(|context| Ok(context.cpu_time_nanos())).unwrap_or(0)
    };
    // SAFETY: `nanos` was checked non-null and is writable per the C ABI.
    unsafe { nanos.write(value) };
    set_errno(0);
    0
}
