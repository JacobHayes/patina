//! time/localtime — glibc's `localtime_r` (time/localtime.c, time/tzset.c)
//! under a POSIX `TZ` rule, `XST5XDT,M3.2.0,M11.1.0`: five hours west of
//! UTC, daylight time (four hours west) from the second Sunday of March to
//! the first Sunday of November, both at 02:00 local. No zoneinfo file is
//! named, so the host's time zone database plays no part. `TZ` is set before
//! the first conversion, which is when glibc reads it (`localtime_r` need not
//! call `tzset`).
//!
//! * the epoch, one second before it, a summer instant, and both sides of the
//!   spring-forward and fall-back instants convert to their exact broken-down time, day of
//!   the week and of the year, daylight flag, UTC offset and zone name;
//! * a time whose year overflows `int` is EOVERFLOW (NULL);
//! * the current time converts consistently with its seconds (the offsets
//!   are whole hours, so seconds and minutes carry over).
//!
//! libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CStr;

const RULE: &CStr = c"XST5XDT,M3.2.0,M11.1.0";

/// `localtime_r(t)`: 0 and the broken-down time, or `-errno`.
fn convert(p: &Probe, t: i64, record: bool) -> (i64, Option<tm>) {
    // SAFETY: an all-zero `struct tm` is a valid out-parameter.
    let mut out: tm = unsafe { std::mem::zeroed() };
    // SAFETY: the calling thread's errno slot, then valid pointers.
    let answer = unsafe {
        *__errno_location() = 0;
        localtime_r(&t, &mut out)
    };
    let (r, out) = if answer.is_null() {
        (-i64::from(errno()), None)
    } else {
        (0, Some(out))
    };
    if record {
        let event = p.rec.event("localtime_r", r).arg("t", t);
        let event = match &out {
            Some(tm) => event
                .field(
                    "date",
                    format!(
                        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                        i64::from(tm.tm_year) + 1900,
                        tm.tm_mon + 1,
                        tm.tm_mday,
                        tm.tm_hour,
                        tm.tm_min,
                        tm.tm_sec
                    ),
                )
                .field("wday", tm.tm_wday)
                .field("yday", tm.tm_yday)
                .field("isdst", tm.tm_isdst)
                .field("gmtoff", tm.tm_gmtoff)
                .field("zone", zone(tm)),
            None => event,
        };
        event.emit();
    }
    (r, out)
}

fn zone(tm: &tm) -> Option<String> {
    // SAFETY: glibc's zone names are NUL-terminated strings it keeps alive.
    (!tm.tm_zone.is_null()).then(|| {
        unsafe { CStr::from_ptr(tm.tm_zone) }
            .to_string_lossy()
            .into_owned()
    })
}

/// Whether `t` converted to exactly this local time.
fn is(out: &Option<tm>, date: [i32; 6], dst: bool, gmtoff: i64, name: &str) -> bool {
    out.as_ref().is_some_and(|tm| {
        [
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
        ] == date
            && (tm.tm_isdst > 0) == dst
            && tm.tm_gmtoff == gmtoff
            && zone(tm).as_deref() == Some(name)
    })
}

pub fn run(p: &Probe) {
    // SAFETY: NUL-terminated strings, copied by setenv.
    let r = unsafe { setenv(c"TZ".as_ptr(), RULE.as_ptr(), 1) };
    p.require("set TZ", r == 0);

    for (t, date, dst, gmtoff, name) in [
        (0, [1969, 12, 31, 19, 0, 0], false, -18_000, "XST"),
        (-1, [1969, 12, 31, 18, 59, 59], false, -18_000, "XST"),
        (
            1_690_000_000,
            [2023, 7, 22, 0, 26, 40],
            true,
            -14_400,
            "XDT",
        ),
        // 2023-03-12 07:00:00 UTC: 02:00 XST springs forward to 03:00 XDT.
        (
            1_678_604_399,
            [2023, 3, 12, 1, 59, 59],
            false,
            -18_000,
            "XST",
        ),
        (1_678_604_400, [2023, 3, 12, 3, 0, 0], true, -14_400, "XDT"),
        // 2023-11-05 06:00:00 UTC: 02:00 XDT falls back to 01:00 XST.
        (
            1_699_163_999,
            [2023, 11, 5, 1, 59, 59],
            true,
            -14_400,
            "XDT",
        ),
        (1_699_164_000, [2023, 11, 5, 1, 0, 0], false, -18_000, "XST"),
    ] {
        let (r, out) = convert(p, t, true);
        p.check(
            &format!("{t} is {date:?} {name}"),
            r == 0 && is(&out, date, dst, gmtoff, name),
        );
    }
    let (r, out) = convert(p, i64::MAX, true);
    p.check(
        "a year past int is EOVERFLOW",
        r == neg(EOVERFLOW) && out.is_none(),
    );

    let (r, now) = p.clock_gettime(CLOCK_REALTIME);
    p.require("read the realtime clock", r == 0);
    let t = (now / 1_000_000_000) as i64;
    let (r, out) = convert(p, t, false);
    p.check(
        "the current time keeps its seconds and minutes",
        r == 0
            && out.as_ref().is_some_and(|tm| {
                i64::from(tm.tm_sec) == t % 60 && i64::from(tm.tm_min) == (t / 60) % 60
            }),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/localtime",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_clock_gettime],
    symbols: &["localtime_r", "setenv", "clock_gettime"],
    ..DEFAULTS
};
