//! time/clock_set — setting and slewing the clock, and the kernel log, as
//! an unprivileged caller (kernel/time/time.c, posix-timers.c,
//! timekeeping.c, printk/printk.c):
//!
//! * `settimeofday` validates its time before the privilege check (a
//!   `tv_usec` of a second or a negative second is `EINVAL`) and is then
//!   `EPERM`, with a NULL time too, and with a time zone alone;
//! * `clock_settime` of `CLOCK_REALTIME` is `EPERM` (a `tv_nsec` of a second
//!   is `EINVAL` first); a clock with no setter (`CLOCK_MONOTONIC`) or an
//!   unknown one is `EINVAL`, and so is the static CPU-time clock id (no
//!   setter either); a process CPU clock id (`clock_getcpuclockid(3)`) is
//!   validated, then `EPERM` even to root (`posix_cpu_clock_set`);
//! * `adjtimex` with no mode, or the read-only single-shot offset mode, only
//!   reads: it answers the clock's state (`TIME_OK` … `TIME_ERROR`, whether
//!   the host is synchronized — recorded as that range); any mode that
//!   writes is `EPERM`, and `ADJ_ADJTIME` without the single-shot offset bit
//!   is `EINVAL` before that;
//! * `clock_adjtime` of `CLOCK_REALTIME` is `adjtimex`; of a clock with no
//!   adjuster (`CLOCK_MONOTONIC`) `EOPNOTSUPP`; of an unknown one `EINVAL`;
//! * the alarm clocks need `CAP_WAKE_ALARM`: a timerfd on one is `EPERM`;
//! * `syslog` actions other than reading the whole log or its size are
//!   `CAP_SYSLOG`'s whatever `dmesg_restrict` says: `EPERM` before an
//!   unknown action is looked at.
//!
//! Root answers differently and a root run would really set the clock, so
//! the scenario needs an unprivileged caller.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{ClockArg, Probe, SetTo, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// The single-shot offset mode (`ADJ_OFFSET_SINGLESHOT`: `ADJ_ADJTIME` plus
/// the kernel's offset bit) and its read-only form.
const ADJ_ADJTIME: u32 = 0x8000;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;
const ADJ_FREQUENCY: u32 = 0x0002;
/// `SYSLOG_ACTION_CLOSE`, `SYSLOG_ACTION_OPEN` and one no kernel defines.
const SYSLOG_ACTION_CLOSE: i32 = 0;
const SYSLOG_ACTION_OPEN: i32 = 1;
const SYSLOG_ACTION_UNKNOWN: i32 = 99;

pub fn run(p: &Probe) {
    p.check(
        "settimeofday with a tv_usec of a second is EINVAL",
        p.settimeofday(Some((0, 1_000_000)), false) == neg(EINVAL),
    );
    p.check(
        "settimeofday with a negative second is EINVAL",
        p.settimeofday(Some((-1, 0)), false) == neg(EINVAL),
    );
    p.check(
        "settimeofday with a NULL time is EPERM",
        p.settimeofday(None, false) == neg(EPERM),
    );
    p.check(
        "settimeofday of a time zone alone is EPERM",
        p.settimeofday(None, true) == neg(EPERM),
    );
    p.check(
        "clock_settime with a tv_nsec of a second is EINVAL",
        p.clock_settime(ClockArg::Id(CLOCK_REALTIME), SetTo::Raw((0, 1_000_000_000)))
            == neg(EINVAL),
    );
    p.check(
        "clock_settime of CLOCK_REALTIME is EPERM",
        p.clock_settime(ClockArg::Id(CLOCK_REALTIME), SetTo::Now) == neg(EPERM),
    );
    p.check(
        "clock_settime of CLOCK_MONOTONIC is EINVAL",
        p.clock_settime(ClockArg::Id(CLOCK_MONOTONIC), SetTo::Raw((1, 0))) == neg(EINVAL),
    );
    p.check(
        "clock_settime of an unknown clock is EINVAL",
        p.clock_settime(ClockArg::Id(1234), SetTo::Raw((1, 0))) == neg(EINVAL),
    );
    p.check(
        "clock_settime of the static CPU-time clock (no setter) is EINVAL",
        p.clock_settime(ClockArg::Id(CLOCK_PROCESS_CPUTIME_ID), SetTo::Raw((1, 0))) == neg(EINVAL),
    );
    let pid = p.getpid() as i32;
    p.check(
        "clock_settime of the caller's own process CPU clock is EPERM",
        p.clock_settime(ClockArg::ProcessCpu(pid), SetTo::Raw((1, 0))) == neg(EPERM),
    );

    p.check(
        "adjtimex with no mode reads the clock state",
        (0..=5).contains(&p.adjtimex(0, 0)),
    );
    p.check(
        "the read-only single-shot offset mode reads too",
        (0..=5).contains(&p.adjtimex(ADJ_OFFSET_SS_READ, 0)),
    );
    p.check(
        "a mode that writes is EPERM",
        p.adjtimex(ADJ_FREQUENCY, 0) == neg(EPERM),
    );
    p.check(
        "ADJ_ADJTIME without the single-shot bit is EINVAL",
        p.adjtimex(ADJ_ADJTIME, 0) == neg(EINVAL),
    );
    p.check(
        "clock_adjtime of CLOCK_REALTIME with no mode reads the state",
        (0..=5).contains(&p.clock_adjtime(CLOCK_REALTIME, 0)),
    );
    p.check(
        "clock_adjtime of CLOCK_REALTIME writing is EPERM",
        p.clock_adjtime(CLOCK_REALTIME, ADJ_FREQUENCY) == neg(EPERM),
    );
    p.check(
        "clock_adjtime of CLOCK_MONOTONIC is EOPNOTSUPP",
        p.clock_adjtime(CLOCK_MONOTONIC, 0) == neg(EOPNOTSUPP),
    );
    p.check(
        "clock_adjtime of an unknown clock is EINVAL",
        p.clock_adjtime(1234, 0) == neg(EINVAL),
    );

    for clock in [CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM] {
        p.check(
            "a timerfd on an alarm clock is EPERM",
            p.timerfd_create(clock, 0) == neg(EPERM) as i32,
        );
    }

    for action in [
        SYSLOG_ACTION_CLOSE,
        SYSLOG_ACTION_OPEN,
        SYSLOG_ACTION_UNKNOWN,
    ] {
        p.check(
            "a syslog action beyond reading is EPERM",
            p.syslog(action, 0) == neg(EPERM),
        );
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/clock_set",
    run,
    covers: &[
        Syscall::N_settimeofday,
        Syscall::N_clock_settime,
        Syscall::N_adjtimex,
        Syscall::N_clock_adjtime,
        Syscall::N_syslog,
    ],
    symbols: &["syscall", "getpid", "clock_gettime"],
    needs: &[Need::Unprivileged],
    gaps: &[Gap {
        status: Status::Pending(Arc::TimeTimersSchedIdentity),
        vehicles: Vehicle::ALL,
        what: "settimeofday is Trap(privileged) in the registry (patina-syscalls linux.rs), so every door aborts by name where an unprivileged kernel caller is answered EINVAL or EPERM (its libc spelling is syscall(2))",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall settimeofday (nr",
        },
    }],
    ..DEFAULTS
};
