//! Clock, sleep and local-time adapters over the shared clock model.
//! Linux keeps its caller-memory clock stores and acting-cancellation sleeps
//! in `c/posix/time.c`, which call the returning helpers here.
use core::ffi::c_int;
use core::ptr::null_mut;

use super::{errno, error};

const NANOS: u64 = 1_000_000_000;
const REALTIME: u32 = 0;
#[cfg(target_os = "macos")]
const MONOTONIC: u32 = 1;

/// The virtual clock `clock` in nanoseconds, or errno set.
fn now(clock: u32) -> Option<u64> {
    let mut nanos = 0;
    // SAFETY: a local out-parameter.
    if unsafe { crate::patina_clock_now(clock, &mut nanos) } != 0 {
        errno(crate::patina_errno());
        return None;
    }
    Some(nanos)
}

/// The realtime clock as whole seconds and microseconds, for the C `time` and
/// `gettimeofday` doors that store it into caller memory themselves.
/// 0, or -1 with errno set.
///
/// # Safety
/// Both pointers name writable storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_time_of_day(seconds: *mut i64, micros: *mut i64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(nanos) = now(REALTIME) else {
        return -1;
    };
    unsafe {
        seconds.write((nanos / NANOS) as i64);
        micros.write((nanos % NANOS / 1000) as i64);
    }
    0
}

/// glibc 2.39's nanosleep is clock_nanosleep(CLOCK_REALTIME, 0, ...) with the
/// answer moved to errno: the row's own copies, so an unreadable request (NULL
/// too) is EFAULT and `remaining` is written only by an interrupted sleep.
#[cfg(target_os = "linux")]
unsafe fn sleep_for(duration: *const libc::timespec, remaining: *mut libc::timespec) -> c_int {
    let result = unsafe {
        crate::clocks::patina_clock_nanosleep(
            libc::CLOCK_REALTIME,
            0,
            duration.cast(),
            remaining.cast(),
        )
    };
    if result < 0 {
        error(-result as c_int)
    } else {
        0
    }
}

/// Darwin has no clock_nanosleep: a relative sleep on the monotonic clock.
#[cfg(target_os = "macos")]
pub(super) unsafe fn sleep_for(
    duration: *const libc::timespec,
    remaining: *mut libc::timespec,
) -> c_int {
    if duration.is_null() {
        return error(libc::EINVAL);
    }
    let duration = unsafe { duration.read() };
    if duration.tv_sec < 0 || !(0..NANOS as libc::c_long).contains(&duration.tv_nsec) {
        return error(libc::EINVAL);
    }
    let Some(now) = now(MONOTONIC) else {
        return -1;
    };
    let Some(deadline) = (duration.tv_sec as u64)
        .checked_mul(NANOS)
        .and_then(|delta| delta.checked_add(duration.tv_nsec as u64))
        .and_then(|delta| delta.checked_add(now))
    else {
        return error(libc::EOVERFLOW);
    };
    if unsafe { crate::patina_sleep_until_remaining(MONOTONIC, deadline, remaining.cast()) } != 0 {
        return error(crate::patina_errno());
    }
    if !remaining.is_null() {
        unsafe {
            remaining.write(libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            })
        };
    }
    0
}

/// The sleep under Linux's C cancellation seams (`nanosleep`, `sleep`).
///
/// # Safety
/// As nanosleep's.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_nanosleep(
    duration: *const libc::timespec,
    remaining: *mut libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { sleep_for(duration, remaining) }
}
#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_nanosleep", ".hidden patina_time_of_day");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_time_of_day");

/// # Safety
/// As nanosleep's.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(
    duration: *const libc::timespec,
    remaining: *mut libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { sleep_for(duration, remaining) }
}

/// sleep() is the whole-second face of the same interruptible sleep. POSIX
/// rounds a fractional unslept second up in its unsigned return value.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub extern "C" fn sleep(seconds: libc::c_uint) -> libc::c_uint {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let duration = libc::timespec {
        tv_sec: seconds.into(),
        tv_nsec: 0,
    };
    let mut remaining = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { sleep_for(&duration, &mut remaining) } == 0 {
        0
    } else if super::get_errno() == libc::EINTR {
        remaining.tv_sec as libc::c_uint + libc::c_uint::from(remaining.tv_nsec != 0)
    } else {
        seconds
    }
}

/// Darwin's clocks: realtime, and monotonic for both monotonic spellings.
///
/// # Safety
/// `time` names writable storage.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(
    clock_id: libc::clockid_t,
    time: *mut libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_boundary_symbol(c"clock_gettime".as_ptr());
    let clock = match clock_id {
        libc::CLOCK_REALTIME => REALTIME,
        libc::CLOCK_MONOTONIC | libc::CLOCK_UPTIME_RAW => MONOTONIC,
        _ => return error(libc::EINVAL),
    };
    let Some(nanos) = now(clock) else {
        return -1;
    };
    unsafe {
        time.write(libc::timespec {
            tv_sec: (nanos / NANOS) as libc::time_t,
            tv_nsec: (nanos % NANOS) as libc::c_long,
        });
    }
    0
}

/// localtime_r: glibc's time zone over the virtual machine (src/localtime.rs):
/// TZ, read at the first call as glibc reads it, names a POSIX rule string or a
/// zoneinfo file; the machine ships no zoneinfo, so a name glibc cannot find a
/// file for answers what glibc answers then (UTC for an unset or empty TZ, the
/// rule string otherwise), and a zoneinfo file the guest put where glibc would
/// read it is a named refusal. A year past `int` is EOVERFLOW.
///
/// # Safety
/// Nonnull pointers follow localtime_r's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime_r(
    timep: *const libc::time_t,
    result: *mut libc::tm,
) -> *mut libc::tm {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if timep.is_null() || result.is_null() {
        error(libc::EFAULT);
        return null_mut();
    }
    let mut tm = crate::localtime::PatinaTm::default();
    let lookup = |name: &core::ffi::CStr| unsafe { crate::posix_env::env_lookup(name.as_ptr()) };
    if unsafe {
        crate::localtime::patina_localtime(*timep, lookup(c"TZ"), lookup(c"TZDIR"), &mut tm)
    } != 0
    {
        errno(crate::patina_errno());
        return null_mut();
    }
    // Field stores through the caller's pointer, never a reference to it.
    unsafe {
        (*result).tm_sec = tm.sec;
        (*result).tm_min = tm.min;
        (*result).tm_hour = tm.hour;
        (*result).tm_mday = tm.mday;
        (*result).tm_mon = tm.mon;
        (*result).tm_year = tm.year;
        (*result).tm_wday = tm.wday;
        (*result).tm_yday = tm.yday;
        (*result).tm_isdst = tm.isdst;
        (*result).tm_gmtoff = tm.gmtoff as libc::c_long;
        (*result).tm_zone = tm.zone as _;
    }
    result
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_localtime_r",
    ".hidden patina_route_localtime_r",
    ".set patina_route_localtime_r, localtime_r"
);
