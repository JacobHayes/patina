//! time/clocks — clock_gettime / gettimeofday / nanosleep / clock_nanosleep:
//! clock ids, monotonicity, sleep advancing the clock, and the errno vocabulary.

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let (r, m1) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check("CLOCK_MONOTONIC reads", r == 0);
    let (_, m2) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check("CLOCK_MONOTONIC never goes backwards", m2 >= m1);
    let (r, rt1) = p.clock_gettime(CLOCK_REALTIME);
    p.check("CLOCK_REALTIME reads", r == 0);
    for clock in [
        CLOCK_BOOTTIME,
        CLOCK_MONOTONIC_RAW,
        CLOCK_MONOTONIC_COARSE,
        CLOCK_REALTIME_COARSE,
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID,
    ] {
        let (r, _) = p.clock_gettime(clock);
        p.check("every standard clock id reads", r == 0);
    }
    let (r, _) = p.clock_gettime(1234);
    p.check("an unknown clock id is EINVAL", r == neg(EINVAL));
    let (r, _) = p.gettimeofday();
    p.check("gettimeofday reads", r == 0);

    p.check("nanosleep 2ms", p.nanosleep(0, 2_000_000) == 0);
    let (_, m3) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the monotonic clock advanced by at least the sleep",
        m3 - m2 >= 2_000_000,
    );
    p.check(
        "nanosleep with tv_nsec >= 1e9 is EINVAL",
        p.nanosleep(0, 1_000_000_000) == neg(EINVAL),
    );
    p.check(
        "nanosleep with a negative tv_sec is EINVAL",
        p.nanosleep(-1, 0) == neg(EINVAL),
    );
    p.check(
        "nanosleep of zero returns immediately",
        p.nanosleep(0, 0) == 0,
    );

    p.check(
        "clock_nanosleep relative 1ms",
        p.clock_nanosleep(CLOCK_MONOTONIC, 0, 0, 1_000_000) == 0,
    );
    let (_, m4) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the relative sleep advanced the clock",
        m4 - m3 >= 1_000_000,
    );
    let deadline = m4 + 1_000_000;
    p.check(
        "clock_nanosleep TIMER_ABSTIME",
        p.clock_nanosleep(
            CLOCK_MONOTONIC,
            TIMER_ABSTIME,
            (deadline / 1_000_000_000) as i64,
            (deadline % 1_000_000_000) as i64,
        ) == 0,
    );
    let (_, m5) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check("the absolute sleep reached its deadline", m5 >= deadline);
    p.check(
        "clock_nanosleep TIMER_ABSTIME in the past returns immediately",
        p.clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, 0, 1) == 0,
    );
    p.check(
        "clock_nanosleep on CLOCK_REALTIME",
        p.clock_nanosleep(CLOCK_REALTIME, 0, 0, 500_000) == 0,
    );
    p.check(
        "clock_nanosleep on an unknown clock is EINVAL",
        p.clock_nanosleep(1234, 0, 0, 1000) == neg(EINVAL),
    );
    // CLOCK_THREAD_CPUTIME_ID is deliberately absent: the kernel answers
    // EOPNOTSUPP while glibc's wrapper answers EINVAL, so the vehicles cannot
    // agree natively (a wrapper fact, not a kernel row).
    p.check(
        "clock_nanosleep with tv_nsec >= 1e9 is EINVAL",
        p.clock_nanosleep(CLOCK_MONOTONIC, 0, 0, 1_000_000_000) == neg(EINVAL),
    );
    let (_, rt2) = p.clock_gettime(CLOCK_REALTIME);
    p.check("CLOCK_REALTIME advanced across the sleeps", rt2 > rt1);
    let (_, us) = p.gettimeofday();
    p.check(
        "gettimeofday agrees with CLOCK_REALTIME to the second",
        (us / 1_000_000 - rt2 / 1_000_000_000).abs() <= 1,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/clocks",
    run,
    covers: &[
        Syscall::N_clock_gettime,
        Syscall::N_gettimeofday,
        Syscall::N_nanosleep,
        Syscall::N_clock_nanosleep,
    ],
    symbols: &[
        "clock_gettime",
        "gettimeofday",
        "nanosleep",
        "clock_nanosleep",
    ],
    ..DEFAULTS
};
