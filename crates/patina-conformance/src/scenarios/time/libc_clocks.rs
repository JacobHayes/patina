//! time/libc_clocks — the glibc spellings of the clock rows no other
//! scenario's libc vehicle calls: `clock_getres`, the internal
//! `__clock_gettime` (GLIBC_PRIVATE, which some static archives call) and
//! `__gettimeofday`. They answer as their rows do:
//!
//! * (needing high-resolution timers) `clock_getres` resolves
//!   `CLOCK_MONOTONIC` to 1 ns, takes a NULL `res`, and refuses an unknown
//!   clock with EINVAL (time/clock_res holds every clock to its row);
//! * `__clock_gettime` reads a clock (the reading compared by relation) and
//!   refuses an unknown one with EINVAL;
//! * `__gettimeofday` reads the realtime clock in microseconds, between two
//!   `clock_gettime` readings taken around it, and zeroes a time zone it is
//!   given (glibc answers `tz` itself, where the row fills in the kernel's
//!   `sys_tz`).
//!
//! libc only.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::observe::Norm;
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

/// The kernel's `struct timezone` (the libc crate's is opaque).
#[repr(C)]
struct Timezone {
    tz_minuteswest: c_int,
    tz_dsttime: c_int,
}

type ClockFn = unsafe extern "C" fn(clockid_t, *mut timespec) -> c_int;

unsafe extern "C" {
    fn __clock_gettime(clock: clockid_t, time: *mut timespec) -> c_int;
    fn __gettimeofday(time: *mut timeval, zone: *mut c_void) -> c_int;
}

/// `clock_getres(clock, res)` (`with_res` false: a NULL `res`).
fn getres(p: &Probe, f: ClockFn, clock: clockid_t, with_res: bool) -> (i64, i64) {
    let mut res = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let out = if with_res {
        &raw mut res
    } else {
        std::ptr::null_mut()
    };
    // SAFETY: clock_getres; `out` is live or NULL.
    let r = fold_errno(i64::from(unsafe { f(clock, out) }));
    let ns = res.tv_sec * 1_000_000_000 + res.tv_nsec;
    let event = p
        .rec
        .event("clock_getres", r)
        .arg("clock", clock)
        .arg("res", with_res);
    let event = if r == 0 && with_res {
        event.field("ns", ns)
    } else {
        event
    };
    event.emit();
    (r, ns)
}

/// `__clock_gettime(clock)`: the result and the reading in nanoseconds.
fn gettime(p: &Probe, f: ClockFn, clock: clockid_t) -> (i64, i128) {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: __clock_gettime into a live timespec.
    let r = fold_errno(i64::from(unsafe { f(clock, &mut ts) }));
    let ns = i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec);
    let event = p.rec.event("__clock_gettime", r).arg("clock", clock);
    let event = if r == 0 {
        event
            .field("ns", ns as i64)
            .norm("fields.ns", Norm::Monotonic)
    } else {
        event
    };
    event.emit();
    (r, ns)
}

pub fn run(p: &Probe) {
    let (getres_fn, gettime_fn): (ClockFn, ClockFn) = (clock_getres, __clock_gettime);

    let (r, ns) = getres(p, getres_fn, CLOCK_MONOTONIC, true);
    p.check("CLOCK_MONOTONIC resolves to 1 ns", r == 0 && ns == 1);
    p.check(
        "a NULL res is not written and succeeds",
        getres(p, getres_fn, CLOCK_MONOTONIC, false).0 == 0,
    );
    p.check(
        "an unknown clock's resolution is EINVAL",
        getres(p, getres_fn, 99, true).0 == neg(EINVAL),
    );

    let (r, first) = gettime(p, gettime_fn, CLOCK_MONOTONIC);
    let (r2, second) = gettime(p, gettime_fn, CLOCK_MONOTONIC);
    p.check(
        "__clock_gettime reads a monotonic clock",
        r == 0 && r2 == 0 && second >= first,
    );
    p.check(
        "an unknown clock is EINVAL",
        gettime(p, gettime_fn, 99).0 == neg(EINVAL),
    );

    let (r, before) = p.clock_gettime(CLOCK_REALTIME);
    let mut tv = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut tz = Timezone {
        tz_minuteswest: 77,
        tz_dsttime: 77,
    };
    // SAFETY: __gettimeofday into a live timeval and timezone.
    let r2 = fold_errno(i64::from(unsafe {
        __gettimeofday(&mut tv, (&raw mut tz).cast())
    }));
    let us = i128::from(tv.tv_sec) * 1_000_000 + i128::from(tv.tv_usec);
    p.rec
        .event("__gettimeofday", r2)
        .field("usec_in_range", (0..1_000_000).contains(&tv.tv_usec))
        .field("minuteswest", tz.tz_minuteswest)
        .field("dsttime", tz.tz_dsttime)
        .emit();
    p.check(
        "__gettimeofday zeroes the time zone",
        tz.tz_minuteswest == 0 && tz.tz_dsttime == 0,
    );
    let (r3, after) = p.clock_gettime(CLOCK_REALTIME);
    p.check(
        "__gettimeofday reads the realtime clock",
        r == 0
            && r2 == 0
            && r3 == 0
            && before / 1_000 <= us
            && us <= after / 1_000
            && (0..1_000_000).contains(&tv.tv_usec),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/libc_clocks",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_clock_getres,
        Syscall::N_clock_gettime,
        Syscall::N_gettimeofday,
    ],
    symbols: &[
        "clock_getres",
        "__clock_gettime",
        "__gettimeofday",
        "clock_gettime",
    ],
    needs: &[Need::HighResTimers],
    ..DEFAULTS
};
