//! SUD rows — clocks and sleeps: `clock_gettime`/`clock_getres`/`gettimeofday`,
//! `nanosleep`/`clock_nanosleep`. Routed to the virtual clock through the same
//! `patina_clock_now`/`patina_sleep_until` entries the C interposers call.

use super::*;

pub(super) fn clock_from_raw(raw: u64) -> Option<u32> {
    // Mirror the C `clock_gettime` interposer: only REALTIME/MONOTONIC route.
    match raw {
        0 => Some(PATINA_CLOCK_REALTIME),
        1 => Some(PATINA_CLOCK_MONOTONIC),
        _ => None,
    }
}

pub(super) fn sys_clock_gettime(clock_raw: u64, out: *mut Timespec) -> i64 {
    let Some(clock) = clock_from_raw(clock_raw) else {
        return -EINVAL;
    };
    if out.is_null() {
        return -EINVAL;
    }
    let mut nanos: u64 = 0;
    // SAFETY: `nanos` is local, writable storage.
    let rc = unsafe { patina_clock_now(clock, &mut nanos) };
    if rc != 0 {
        return ret_i32(rc);
    }
    // SAFETY: `out` is a guest pointer to `struct timespec` storage.
    unsafe {
        out.write(Timespec {
            tv_sec: (nanos / NANOS_PER_SEC) as i64,
            tv_nsec: (nanos % NANOS_PER_SEC) as i64,
        });
    }
    0
}

pub(super) fn sys_clock_getres(clock_raw: u64, out: *mut Timespec) -> i64 {
    // Resolution of the virtual clock is 1ns; report it deterministically.
    if clock_from_raw(clock_raw).is_none() {
        return -EINVAL;
    }
    if !out.is_null() {
        // SAFETY: `out` is a guest `struct timespec` pointer.
        unsafe {
            out.write(Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            });
        }
    }
    0
}

pub(super) fn sys_gettimeofday(out: *mut Timeval) -> i64 {
    if out.is_null() {
        return 0;
    }
    let mut nanos: u64 = 0;
    // SAFETY: local storage.
    let rc = unsafe { patina_clock_now(PATINA_CLOCK_REALTIME, &mut nanos) };
    if rc != 0 {
        return ret_i32(rc);
    }
    // SAFETY: `out` is a guest `struct timeval` pointer.
    unsafe {
        out.write(Timeval {
            tv_sec: (nanos / NANOS_PER_SEC) as i64,
            tv_usec: ((nanos % NANOS_PER_SEC) / 1000) as i64,
        });
    }
    0
}

/// Read a `struct timespec` from guest memory and validate it, returning its
/// value in nanoseconds or an `-errno`.
pub(super) fn read_timespec_nanos(ptr: *const Timespec) -> Result<u64, i64> {
    if ptr.is_null() {
        return Err(-EINVAL);
    }
    // SAFETY: `ptr` is a guest `struct timespec` pointer.
    let ts = unsafe { ptr.read() };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NANOS_PER_SEC as i64 {
        return Err(-EINVAL);
    }
    let seconds = ts.tv_sec as u64;
    if seconds > u64::MAX / NANOS_PER_SEC {
        return Err(-EINVAL);
    }
    Ok(seconds * NANOS_PER_SEC + ts.tv_nsec as u64)
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
    clock_raw: u64,
    flags: u64,
    req: *const Timespec,
    rem: *mut Timespec,
) -> i64 {
    let Some(clock) = clock_from_raw(clock_raw) else {
        return -EINVAL;
    };
    let requested = match read_timespec_nanos(req) {
        Ok(nanos) => nanos,
        Err(errno) => return errno,
    };
    let deadline = if flags & TIMER_ABSTIME != 0 {
        requested
    } else {
        let mut now: u64 = 0;
        // SAFETY: local storage.
        let rc = unsafe { patina_clock_now(clock, &mut now) };
        if rc != 0 {
            return ret_i32(rc);
        }
        now.saturating_add(requested)
    };
    // SAFETY: no pointers.
    ret_i32(unsafe {
        patina_sleep_until_remaining(
            clock,
            deadline,
            if flags & TIMER_ABSTIME == 0 {
                rem.cast()
            } else {
                std::ptr::null_mut()
            },
        )
    })
}
