//! sys/perf — performance events (kernel/events/core.c `perf_event_open`),
//! on a host that refuses them to an unprivileged caller altogether
//! (`Need::RestrictedPerf`; the virtual kernel declares Ubuntu's
//! `perf_event_paranoid` 4, at which its patch refuses every event). An
//! unknown flag is `EINVAL` first; then every event is `EACCES` without
//! `CAP_PERFMON` or `CAP_SYS_ADMIN`, before the attribute is even read:
//! counting the caller's own user time and an unreadable attribute alike.
//!
//! What root would be granted is a disabled software counter of its own
//! time, closed at exit.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// Outside `PERF_FLAG_ALL`.
const UNKNOWN_FLAG: i64 = 0x100;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
const DISABLED: u64 = 1;
const EXCLUDE_KERNEL: u64 = 1 << 5;
const EXCLUDE_HV: u64 = 1 << 6;

/// `struct perf_event_attr`, `PERF_ATTR_SIZE_VER0` bytes.
#[repr(C)]
struct Attr {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let clock = |flags: u64| Attr {
        kind: PERF_TYPE_SOFTWARE,
        size: std::mem::size_of::<Attr>() as u32,
        config: PERF_COUNT_SW_TASK_CLOCK,
        sample_period: 0,
        sample_type: 0,
        read_format: 0,
        flags,
        wakeup_events: 0,
        bp_type: 0,
        config1: 0,
    };
    let open = |attr: *const Attr, flags: i64| {
        p.call_observed(
            Syscall::N_perf_event_open,
            [attr as i64, 0, -1, -1, flags, 0],
        )
    };
    let user = clock(DISABLED | EXCLUDE_KERNEL | EXCLUDE_HV);
    p.check(
        "an unknown flag is EINVAL first",
        open(&user, UNKNOWN_FLAG) == neg(EINVAL),
    );
    p.check(
        "counting its own user time is EACCES",
        open(&user, 0) == neg(EACCES),
    );
    p.check(
        "an unreadable attribute is EACCES: refused before it is read",
        open(std::ptr::null(), 0) == neg(EACCES),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/perf",
    run,
    // glibc has no wrapper for the row: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_perf_event_open],
    needs: &[Need::Unprivileged, Need::RestrictedPerf],
    ..DEFAULTS
};
