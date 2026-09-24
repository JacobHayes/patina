//! SUD rows — clocks, sleeps and the clock-setting rows:
//! `clock_gettime`/`clock_getres`/`gettimeofday`/`time`,
//! `nanosleep`/`clock_nanosleep`, and `settimeofday`/`clock_settime`/
//! `adjtimex`/`clock_adjtime`. Every clock id is decoded once, in
//! `crate::clocks`, which the C interposers call too.

use super::*;

pub(super) fn sys_clock_gettime(clock: u64, out: *mut Timespec) -> i64 {
    // SAFETY: `out` is the guest's `struct timespec` pointer (NULL: EFAULT).
    unsafe { crate::clocks::patina_clock_gettime(clock as c_int, out) }
}

pub(super) fn sys_clock_getres(clock: u64, out: *mut Timespec) -> i64 {
    // SAFETY: `out` is NULL or the guest's `struct timespec`.
    unsafe { crate::clocks::patina_clock_getres(clock as c_int, out) }
}

/// `gettimeofday(2)`: the realtime clock into a non-NULL `tv`; a non-NULL
/// `tz` gets the kernel's time zone, which nobody set (0 minutes west, no
/// DST correction).
pub(super) fn sys_gettimeofday(out: *mut Timeval, zone: *mut [i32; 2]) -> i64 {
    if !out.is_null() {
        let nanos = match crate::clocks::read(crate::clocks::Clock::Realtime) {
            Ok(nanos) => nanos,
            Err(errno) => return crate::neg_errno(errno),
        };
        // SAFETY: `out` is a guest `struct timeval` pointer.
        unsafe { out.write(crate::clocks::Timeval::from_nanos(nanos)) };
    }
    if !zone.is_null() {
        // SAFETY: `zone` is a guest `struct timezone` pointer.
        unsafe { zone.write_unaligned([0, 0]) };
    }
    0
}

/// `time(2)`: whole seconds of the realtime clock, stored through a
/// non-NULL pointer too. The kernel answers the timekeeper's seconds as of
/// its last tick (`ktime_get_real_seconds`), i.e. the coarse realtime clock,
/// which may trail a fine reading across a second boundary by up to a tick.
#[cfg(target_arch = "x86_64")]
pub(super) fn sys_time(out: *mut i64) -> i64 {
    let nanos = match crate::clocks::read(crate::clocks::Clock::RealtimeCoarse) {
        Ok(nanos) => nanos,
        Err(errno) => return crate::neg_errno(errno),
    };
    let seconds = (nanos / NANOS_PER_SEC) as i64;
    if !out.is_null() {
        // SAFETY: `out` is the guest's `time_t`.
        unsafe { out.write_unaligned(seconds) };
    }
    seconds
}

/// Read a `struct timespec` from guest memory and validate it, returning its
/// value in nanoseconds or an `-errno`.
pub(super) fn read_timespec_nanos(ptr: *const Timespec) -> Result<u64, i64> {
    if ptr.is_null() {
        return Err(-EINVAL);
    }
    // SAFETY: `ptr` is a guest `struct timespec` pointer.
    unsafe { ptr.read() }.valid_nanos().ok_or(-EINVAL)
}

pub(super) fn sys_nanosleep(req: *const Timespec, rem: *mut Timespec) -> i64 {
    // Relative CLOCK_MONOTONIC sleep. Convert to an absolute virtual deadline.
    let rel = match read_timespec_nanos(req) {
        Ok(nanos) => nanos,
        Err(errno) => return errno,
    };
    let mut now: u64 = 0;
    // SAFETY: local storage.
    let rc = unsafe { patina_clock_now(PATINA_CLOCK_MONOTONIC, &mut now) };
    if rc != 0 {
        return ret_i32(rc);
    }
    let deadline = now.saturating_add(rel);
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_sleep_until_remaining(PATINA_CLOCK_MONOTONIC, deadline, rem.cast()) })
}

pub(super) fn sys_clock_nanosleep(
    clock: u64,
    flags: u64,
    req: *const Timespec,
    rem: *mut Timespec,
) -> i64 {
    // SAFETY: guest pointers, NULL-checked by the entry.
    unsafe { crate::clocks::patina_clock_nanosleep(clock as c_int, flags as c_int, req, rem) }
}
