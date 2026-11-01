//! Clock, sleep and local-time adapters over the shared clock model.
//! Linux keeps its caller-memory clock stores and acting-cancellation sleeps
//! in `c/posix/time.c`, which call the returning helpers here.
#![deny(clippy::undocumented_unsafe_blocks)]

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
    let _panic_scope = crate::panic_boundary::PanicScope::enter_op(crate::charge::Op::TimeOfDay);
    let Some(nanos) = now(REALTIME) else {
        return -1;
    };
    // SAFETY: this door's contract requires both aligned outputs to be writable.
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
    // SAFETY: the helper's caller contract matches the clock model's pointer
    // contract; this forwards the original pointers unchanged.
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
    // SAFETY: nonnull pointers were checked above; the helper contract supplies
    // aligned, live `timespec` storage for the duration of this call.
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
    // SAFETY: nonnull `remaining` follows nanosleep's writable-output contract.
    if unsafe { crate::patina_sleep_until_remaining(MONOTONIC, deadline, remaining.cast()) } != 0 {
        return error(crate::patina_errno());
    }
    if !remaining.is_null() {
        // SAFETY: nonnull `remaining` is aligned writable output per the helper contract.
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
    // SAFETY: the door and helper share nanosleep's pointer contract.
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
unsafe extern "C" fn nanosleep(
    duration: *const libc::timespec,
    remaining: *mut libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the door and helper share nanosleep's pointer contract.
    unsafe { sleep_for(duration, remaining) }
}

/// sleep() is the whole-second face of the same interruptible sleep. POSIX
/// rounds a fractional unslept second up in its unsigned return value.
#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
extern "C" fn sleep(seconds: libc::c_uint) -> libc::c_uint {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let duration = libc::timespec {
        tv_sec: seconds.into(),
        tv_nsec: 0,
    };
    let mut remaining = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: both pointers refer to aligned local timespec values for this call.
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
unsafe extern "C" fn clock_gettime(clock_id: libc::clockid_t, time: *mut libc::timespec) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_op(crate::charge::Op::ClockGettime);
    crate::patina_note_boundary_symbol(c"clock_gettime".as_ptr());
    // SAFETY: as this door's contract.
    unsafe { read_clock(clock_id, time) }
}

/// The guest's read of `clock_id` into `time`, for `clock_gettime` and the
/// waits that read the clock as part of their own call.
///
/// # Safety
/// `time` names writable storage.
#[cfg(target_os = "macos")]
pub(super) unsafe fn read_clock(clock_id: libc::clockid_t, time: *mut libc::timespec) -> c_int {
    let clock = match clock_id {
        libc::CLOCK_REALTIME => REALTIME,
        libc::CLOCK_MONOTONIC | libc::CLOCK_UPTIME_RAW => MONOTONIC,
        _ => return error(libc::EINVAL),
    };
    let Some(nanos) = now(clock) else {
        return -1;
    };
    // SAFETY: `time` is writable and aligned for one timespec per this door's contract.
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
unsafe extern "C" fn localtime_r(
    timep: *const libc::time_t,
    result: *mut libc::tm,
) -> *mut libc::tm {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if timep.is_null() || result.is_null() {
        error(libc::EFAULT);
        return null_mut();
    }
    // SAFETY: nonnull, and readable per localtime_r's contract.
    let t = unsafe { *timep };
    // SAFETY: nonnull, and writable per localtime_r's contract.
    unsafe { broken_down(zone("localtime_r", false).local(t), result) }
}

/// gmtime_r: `timep` broken down in UTC (`localtime::universal`), with no
/// time zone read: glibc reads its zone files here too, for leap seconds,
/// which the machine has none of. A year past `int` is EOVERFLOW.
///
/// # Safety
/// Nonnull pointers follow gmtime_r's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn gmtime_r(timep: *const libc::time_t, result: *mut libc::tm) -> *mut libc::tm {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if timep.is_null() || result.is_null() {
        error(libc::EFAULT);
        return null_mut();
    }
    // SAFETY: nonnull, and readable per gmtime_r's contract.
    let t = unsafe { *timep };
    // SAFETY: nonnull, and writable per gmtime_r's contract.
    unsafe { broken_down(crate::localtime::universal(t), result) }
}

/// A breakdown into the caller's `struct tm`: `result`, or NULL with errno.
///
/// # Safety
/// `result` names aligned, live, writable `struct tm` storage.
unsafe fn broken_down(
    tm: Result<crate::localtime::PatinaTm, libc::c_int>,
    result: *mut libc::tm,
) -> *mut libc::tm {
    match tm {
        Ok(tm) => {
            // SAFETY: as this function's contract.
            unsafe { store_tm(result, &tm) };
            result
        }
        Err(errno_value) => {
            errno(errno_value);
            null_mut()
        }
    }
}

/// Every field of `tm` into the caller's `struct tm`, through the pointer and
/// never a reference to it.
///
/// # Safety
/// `result` names aligned, live, writable `struct tm` storage.
unsafe fn store_tm(result: *mut libc::tm, tm: &crate::localtime::PatinaTm) {
    // SAFETY: as this function's contract.
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
}

/// The zone in effect, `TZ` read again first when `reread` (glibc's
/// `tzset_internal`; see `localtime::current`).
fn zone(op: &str, reread: bool) -> crate::localtime::Zone {
    let lookup = |name: &core::ffi::CStr| {
        // SAFETY: env_lookup accepts a static NUL-terminated key and answers
        // NULL or a NUL-terminated value that lives for this call.
        let value = unsafe { crate::posix_env::env_lookup(name.as_ptr()) };
        if value.is_null() {
            return None;
        }
        // SAFETY: nonnull, and NUL-terminated as above.
        let value = unsafe { core::ffi::CStr::from_ptr(value) };
        Some(value.to_bytes().to_vec())
    };
    crate::localtime::current(op, &|| (lookup(c"TZ"), lookup(c"TZDIR")), reread)
}

/// tzset: glibc's `tzset_internal (1)`: `TZ` read again, unless it is the
/// string the zone in effect was read from. The `tzname`, `timezone` and
/// `daylight` variables are glibc's, which this does not set; a guest that
/// reads them is refused at the audit, as an import the shim does not define.
#[unsafe(no_mangle)]
extern "C" fn tzset() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    zone("tzset", true);
}

/// mktime: the zone model's inverse (`localtime::Zone::mktime`) after
/// glibc's `tzset`, the normalized fields stored back. `EOVERFLOW` leaves
/// `tm` unwritten, as glibc does.
///
/// # Safety
/// Nonnull `tm` follows mktime's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn mktime(tm: *mut libc::tm) -> libc::time_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if tm.is_null() {
        error(libc::EFAULT);
        return -1;
    }
    // SAFETY: nonnull, and mktime's contract makes it a `struct tm` whose
    // input fields are readable.
    let fields = unsafe { mktime_input(tm) };
    match zone("mktime", true).mktime(&fields) {
        Ok((t, normalized)) => {
            // SAFETY: nonnull, and mktime's contract makes it writable.
            unsafe { store_tm(tm, &normalized) };
            t as libc::time_t
        }
        Err(errno_value) => {
            errno(errno_value);
            -1
        }
    }
}

/// The fields `mktime` reads of the caller's `struct tm`, each through the
/// pointer: its others are outputs a caller may leave unset.
///
/// # Safety
/// `tm` names a `struct tm` whose time and `tm_isdst` fields are readable.
unsafe fn mktime_input(tm: *const libc::tm) -> crate::localtime::PatinaTm {
    // SAFETY: as this function's contract.
    unsafe {
        crate::localtime::PatinaTm {
            sec: (*tm).tm_sec,
            min: (*tm).tm_min,
            hour: (*tm).tm_hour,
            mday: (*tm).tm_mday,
            mon: (*tm).tm_mon,
            year: (*tm).tm_year,
            isdst: (*tm).tm_isdst,
            ..Default::default()
        }
    }
}

/// strftime's view of the caller's time beyond its fields: its own zone
/// name, and the zone in effect's names for `%Z` and `mktime` for `%s`, each
/// after glibc's `tzset`.
struct LiveZone(*const libc::tm);

impl crate::strftime::Zone for LiveZone {
    fn own_name(&self) -> Option<Vec<u8>> {
        // SAFETY: the time strftime was given, readable per its contract.
        let zone = unsafe { (*self.0).tm_zone };
        if zone.is_null() {
            return None;
        }
        // SAFETY: nonnull, and a NUL-terminated name per strftime's
        // contract for a `%Z` conversion, the only one that reads it.
        let name = unsafe { core::ffi::CStr::from_ptr(zone.cast()) };
        Some(name.to_bytes().to_vec())
    }

    fn name(&self, isdst: bool) -> Vec<u8> {
        zone("strftime", true).name(isdst).to_bytes().to_vec()
    }

    fn mktime(&self, tm: &crate::strftime::Tm) -> i64 {
        let fields = crate::localtime::PatinaTm {
            sec: tm.sec,
            min: tm.min,
            hour: tm.hour,
            mday: tm.mday,
            mon: tm.mon,
            year: tm.year,
            isdst: tm.isdst,
            ..Default::default()
        };
        zone("strftime", true)
            .mktime(&fields)
            .map_or(-1, |(t, _)| t)
    }
}

/// The formatter's view of the caller's `struct tm`.
///
/// # Safety
/// `tm` names a readable `struct tm`.
unsafe fn format_tm(tm: *const libc::tm) -> crate::strftime::Tm {
    // SAFETY: as this function's contract.
    unsafe {
        crate::strftime::Tm {
            sec: (*tm).tm_sec,
            min: (*tm).tm_min,
            hour: (*tm).tm_hour,
            mday: (*tm).tm_mday,
            mon: (*tm).tm_mon,
            year: (*tm).tm_year,
            wday: (*tm).tm_wday,
            yday: (*tm).tm_yday,
            isdst: (*tm).tm_isdst,
            gmtoff: (*tm).tm_gmtoff,
        }
    }
}

/// The `strftime` and `wcsftime` answer: the formatted units and a NUL into
/// `out` when they fit `max` units, their count; 0 otherwise (`EILSEQ` for
/// a wide zone name with no wide form).
///
/// # Safety
/// `format` is NUL-terminated (a zero unit), `tm` names a readable
/// `struct tm` (its `tm_zone` NULL or NUL-terminated when `%Z` reads it), and
/// `out` names `max` writable units.
unsafe fn format_into<U: crate::strftime::Unit + Default + PartialEq>(
    out: *mut U,
    max: usize,
    format: *const U,
    tm: *const libc::tm,
) -> usize {
    if out.is_null() || format.is_null() || tm.is_null() {
        error(libc::EFAULT);
        return 0;
    }
    let mut length = 0;
    // SAFETY: NUL-terminated, per this function's contract.
    while unsafe { *format.add(length) } != U::default() {
        length += 1;
    }
    // SAFETY: `length` units precede the terminator just found.
    let format = unsafe { core::slice::from_raw_parts(format, length) };
    // SAFETY: as this function's contract.
    let fields = unsafe { format_tm(tm) };
    // The answer leaves room for its NUL.
    let Some(limit) = max.checked_sub(1) else {
        return 0;
    };
    let formatted = match crate::strftime::format(format, &fields, &LiveZone(tm), limit) {
        Ok(formatted) => formatted,
        Err(crate::strftime::Failure::Overflow) => return 0,
        Err(crate::strftime::Failure::Ilseq) => {
            error(libc::EILSEQ);
            return 0;
        }
    };
    // SAFETY: `out` names `max` units, and the answer and its NUL fit them.
    unsafe {
        core::ptr::copy_nonoverlapping(formatted.as_ptr(), out, formatted.len());
        out.add(formatted.len()).write(U::default());
    }
    formatted.len()
}

/// strftime: glibc 2.39's C-locale formatter (src/strftime.rs) over the zone
/// model.
///
/// # Safety
/// As strftime's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn strftime(
    out: *mut core::ffi::c_char,
    max: usize,
    format: *const core::ffi::c_char,
    tm: *const libc::tm,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: strftime's contract is the helper's, in bytes.
    unsafe { format_into(out.cast::<u8>(), max, format.cast::<u8>(), tm) }
}

/// A `wchar_t`, as the formatter's code unit: a code point.
#[derive(Clone, Copy, Default, PartialEq)]
#[repr(transparent)]
struct Wide(libc::wchar_t);

impl From<u8> for Wide {
    fn from(byte: u8) -> Self {
        Wide(libc::wchar_t::from(byte))
    }
}

impl crate::strftime::Unit for Wide {
    const WIDE: bool = true;
}

impl From<Wide> for u32 {
    fn from(unit: Wide) -> u32 {
        // `wchar_t` is `i32` or `u32` by platform; a negative one is no
        // character the formatter knows, as any value past ASCII is not.
        i64::from(unit.0) as u32
    }
}

/// wcsftime: strftime in wide characters, the same formatter.
///
/// # Safety
/// As wcsftime's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn wcsftime(
    out: *mut libc::wchar_t,
    max: usize,
    format: *const libc::wchar_t,
    tm: *const libc::tm,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: wcsftime's contract is the helper's, in `wchar_t` units, which
    // `Wide` is transparently.
    unsafe { format_into(out.cast::<Wide>(), max, format.cast::<Wide>(), tm) }
}

/// clock: the process's CPU time in `CLOCKS_PER_SEC` (1 000 000) units, as
/// glibc reads it (`CLOCK_PROCESS_CPUTIME_ID`) and Darwin does (user plus
/// system time).
#[unsafe(no_mangle)]
extern "C" fn clock() -> libc::clock_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        let mut time = crate::clocks::Timespec::default();
        // SAFETY: a local out-parameter.
        let result = unsafe {
            crate::clocks::patina_clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time)
        };
        if result < 0 {
            errno(-result as c_int);
            return -1;
        }
        (time.tv_sec * 1_000_000 + time.tv_nsec / 1000) as libc::clock_t
    }
    #[cfg(target_os = "macos")]
    {
        let time = crate::time_abi::cpu_time();
        ((time.user_ns + time.system_ns) / 1000) as libc::clock_t
    }
}

/// times: the process's CPU time and the elapsed clock in clock ticks. Linux
/// forwards to the `times` row; Darwin answers as its libc does, from the
/// CPU time and the realtime clock, at its 100 ticks a second.
///
/// # Safety
/// Nonnull `buffer` follows times's contract.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_times"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn times(buffer: *mut libc::tms) -> libc::clock_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        use crate::sud::Word;
        // SAFETY: `buffer` is the caller's output pointer for this synchronous syscall.
        unsafe { crate::sud::forward_word(libc::SYS_times, &[buffer.word()]) as libc::clock_t }
    }
    #[cfg(target_os = "macos")]
    {
        const TICKS: u64 = 100;
        let ticks = |nanos: u64| (nanos / (NANOS / TICKS)) as libc::clock_t;
        if !buffer.is_null() {
            let time = crate::time_abi::cpu_time();
            // SAFETY: nonnull, and times's contract makes it writable.
            unsafe {
                buffer.write(libc::tms {
                    tms_utime: ticks(time.user_ns),
                    tms_stime: ticks(time.system_ns),
                    tms_cutime: 0,
                    tms_cstime: 0,
                })
            };
        }
        let Some(nanos) = now(REALTIME) else {
            // `(clock_t) -1`: Darwin's `clock_t` is unsigned.
            return libc::clock_t::MAX;
        };
        ticks(nanos)
    }
}

/// clock_settime: Linux forwards to the `clock_settime` row (an unprivileged
/// caller: `EINVAL` or `EPERM`); Darwin answers its unprivileged caller the
/// same way, `EPERM` for the realtime clock and `EINVAL` for every other.
///
/// # Safety
/// Nonnull `time` follows clock_settime's contract.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_clock_settime"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn clock_settime(
    clock_id: libc::clockid_t,
    time: *const libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        use crate::sud::Word;
        // SAFETY: `time` is the caller's input pointer for this synchronous syscall.
        unsafe { crate::sud::forward(libc::SYS_clock_settime, &[clock_id.word(), time.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = time;
        error(if clock_id == libc::CLOCK_REALTIME {
            libc::EPERM
        } else {
            libc::EINVAL
        })
    }
}
