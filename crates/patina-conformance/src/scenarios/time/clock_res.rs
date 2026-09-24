//! time/clock_res — `clock_getres` per clock and `time(2)`:
//!
//! * (needing high-resolution timers, a kernel-configuration fact) every
//!   high-resolution clock (`REALTIME`, `MONOTONIC`, `MONOTONIC_RAW`,
//!   `BOOTTIME`, `TAI`: `hrtimer_resolution`; the scheduler's CPU clocks,
//!   `posix_cpu_clock_getres`) resolves to 1 ns; a coarse clock resolves to
//!   one tick (`TICK_NSEC`, one second over the host's `CONFIG_HZ`, recorded
//!   by that relation);
//! * a NULL `res` is not written and succeeds; an unknown clock is `EINVAL`,
//!   with or without a `res`; a process CPU clock id
//!   (`clock_getcpuclockid(3)`) of the caller resolves, one of a pid no
//!   process has is `EINVAL`;
//! * `sleep(3)` sleeps the whole second it is asked for and answers 0;
//! * `time(2)` answers whole `CLOCK_REALTIME` seconds, stores them through a
//!   pointer, and lies between realtime readings taken around it (the row
//!   reads the coarse clock, so it may trail a precise reading by a tick).
//!   The generic (arm64) table has no `time` row: there the libc vehicle
//!   calls glibc's `time` and the syscall vehicle reads `CLOCK_REALTIME`.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{ClockArg, Probe, Res, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

pub fn run(p: &Probe) {
    for clock in [
        CLOCK_REALTIME,
        CLOCK_MONOTONIC,
        CLOCK_MONOTONIC_RAW,
        CLOCK_BOOTTIME,
        CLOCK_TAI,
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID,
    ] {
        let (r, ns) = p.clock_getres(ClockArg::Id(clock), false, Res::Exact);
        p.check(
            "a high-resolution clock resolves to 1 ns",
            r == 0 && ns == 1,
        );
    }
    for clock in [CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE] {
        let (r, ns) = p.clock_getres(ClockArg::Id(clock), false, Res::Tick);
        p.check(
            "a coarse clock resolves to one tick",
            r == 0 && (1_000_000..=10_000_000).contains(&ns),
        );
    }
    p.check(
        "a NULL res succeeds",
        p.clock_getres(ClockArg::Id(CLOCK_MONOTONIC), true, Res::Exact)
            .0
            == 0,
    );
    p.check(
        "an unknown clock is EINVAL",
        p.clock_getres(ClockArg::Id(1234), false, Res::Exact).0 == neg(EINVAL),
    );
    p.check(
        "an unknown clock with a NULL res is EINVAL",
        p.clock_getres(ClockArg::Id(1234), true, Res::Exact).0 == neg(EINVAL),
    );
    let pid = p.getpid() as i32;
    let (r, ns) = p.clock_getres(ClockArg::ProcessCpu(pid), false, Res::Exact);
    p.check(
        "the caller's own process CPU clock resolves to 1 ns",
        r == 0 && ns == 1,
    );
    p.check(
        "the CPU clock of a pid no process has is EINVAL",
        p.clock_getres(ClockArg::MissingProcessCpu, false, Res::Exact)
            .0
            == neg(EINVAL),
    );

    let (_, start) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    // The sleep symbol's row: one second is the least `sleep(3)` takes
    // (its nanosecond cousins are time/clocks'). SAFETY: no pointer.
    let left = unsafe { sleep(1) };
    let (_, end) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    p.mark(
        "sleep",
        &[
            ("left", Value::from(left)),
            ("slept_a_second", Value::from(end - start >= 1_000_000_000)),
        ],
    );
    p.check(
        "sleep(1) sleeps the whole second, answering 0",
        left == 0 && end - start >= 1_000_000_000,
    );

    let before = p.realtime_seconds();
    let (t, stored) = p.time(true);
    let (t2, _) = p.time(false);
    let after = p.realtime_seconds();
    p.check("time answers seconds", t >= 0 && t2 >= 0);
    p.check("time stores what it answers", stored == t);
    p.check(
        "time lies between the realtime readings around it",
        before - 1 <= t && t <= t2 && t2 <= after,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/clock_res",
    run,
    covers: &[
        Syscall::N_clock_getres,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_time,
    ],
    symbols: &["syscall", "time", "getpid", "sleep", "clock_gettime"],
    needs: &[Need::HighResTimers],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::TimeTimersSchedIdentity),
            vehicles: Vehicle::ALL,
            what: "clock_getres answers only CLOCK_REALTIME and CLOCK_MONOTONIC (SUD sys_clock_getres over clock_from_raw, src/sud/time.rs; its libc spelling is syscall(2), the symbol row being Absent): MONOTONIC_RAW, BOOTTIME, TAI, both CPU-time clocks, both coarse clocks and a process CPU clock id answer EINVAL",
            failure: Failure::Differs(&[
                Difference::field(4, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(4, "clock_getres", "fields.res_ns", Observed::Null),
                Difference::field(4, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(5, "a high-resolution clock resolves to 1 ns"),
                Difference::field(6, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(6, "clock_getres", "fields.res_ns", Observed::Null),
                Difference::field(6, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(7, "a high-resolution clock resolves to 1 ns"),
                Difference::field(8, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(8, "clock_getres", "fields.res_ns", Observed::Null),
                Difference::field(8, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(9, "a high-resolution clock resolves to 1 ns"),
                Difference::field(10, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(10, "clock_getres", "fields.res_ns", Observed::Null),
                Difference::field(10, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(11, "a high-resolution clock resolves to 1 ns"),
                Difference::field(12, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(12, "clock_getres", "fields.res_ns", Observed::Null),
                Difference::field(12, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(13, "a high-resolution clock resolves to 1 ns"),
                Difference::field(14, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(14, "clock_getres", "fields.res_is_a_tick", Observed::Null),
                Difference::field(14, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(15, "a coarse clock resolves to one tick"),
                Difference::field(16, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(16, "clock_getres", "fields.res_is_a_tick", Observed::Null),
                Difference::field(16, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(17, "a coarse clock resolves to one tick"),
                Difference::field(25, "clock_getres", "errno", Observed::Str("EINVAL")),
                Difference::field(25, "clock_getres", "fields.res_ns", Observed::Null),
                Difference::field(25, "clock_getres", "ret", Observed::Int(-1)),
                Difference::check(26, "the caller's own process CPU clock resolves to 1 ns"),
            ]),
        },
        // The generic (arm64) table has no time row: its syscall vehicle reads
        // CLOCK_REALTIME, which is modeled.
        #[cfg(target_arch = "x86_64")]
        Gap {
            status: Status::Pending(Arc::TimeTimersSchedIdentity),
            vehicles: &[
                Vehicle::Syscall,
                #[cfg(target_arch = "x86_64")]
                Vehicle::Raw,
            ],
            what: "time is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the syscall(2) and raw doors abort by name (the libc door reaches the shim's modeled time interposer)",
            failure: Failure::Stops {
                events: 31,
                ending: crate::compare::Ending::Signal(libc::SIGABRT),
                diagnostic: "patina: SUD trapped unsupported syscall time (nr",
            },
        },
    ],
    ..DEFAULTS
};
