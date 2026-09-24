//! sys/sysinfo — the system summary (kernel/sys.c do_sysinfo): on a 64-bit
//! kernel `mem_unit` is 1 and there is no high memory; free memory is at
//! most total memory, and so is free plus buffer memory (disjoint pages);
//! shared memory too, free swap at most total swap; total memory and the
//! process count are positive; the uptime is exactly the boot clock's
//! seconds rounded up (`tv_sec + (tv_nsec ? 1 : 0)`), so it lies between
//! `CLOCK_BOOTTIME` read before and after, rounded up the same way (both
//! sides from one clock: no wall-time bound); it never decreases; a NULL
//! buffer is `EFAULT`.
//!
//! The sizes, the load and the process count are the host's, recorded as
//! those relations. Declared modeled difference: the virtual kernel's
//! memory and uptime are its own constants and clock.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let ceil_seconds = |ns: i128| (ns + 999_999_999).div_euclid(1_000_000_000);
    let (read_before, before) = p.rec.quiet(|| p.clock_gettime(CLOCK_BOOTTIME));
    let (r, first) = p.sysinfo(false);
    let (read_after, after) = p.rec.quiet(|| p.clock_gettime(CLOCK_BOOTTIME));
    p.check("sysinfo answers", r == 0);
    p.check(
        "the uptime is the boot clock's seconds rounded up, read between two readings",
        read_before == 0
            && read_after == 0
            && ceil_seconds(before) <= i128::from(first.uptime)
            && i128::from(first.uptime) <= ceil_seconds(after),
    );
    let (r, second) = p.sysinfo(false);
    p.check(
        "the uptime never decreases",
        r == 0 && second.uptime >= first.uptime,
    );
    p.check("a NULL buffer is EFAULT", p.sysinfo(true).0 == neg(EFAULT));
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/sysinfo",
    run,
    covers: &[Syscall::N_sysinfo],
    symbols: &["sysinfo", "clock_gettime"],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::TimeTimersSchedIdentity),
            vehicles: &[Vehicle::Libc],
            what: "the libc door reaches the shim's fixed sysinfo interposer (c/posix/sched_identity.c), whose uptime is virtual monotonic seconds, while CLOCK_BOOTTIME answers EINVAL (the C clock_gettime interposer routes only REALTIME/MONOTONIC, c/posix/time.c), so the boot-clock relation cannot hold",
            failure: Failure::Differs(&[Difference::check(
                2,
                "the uptime is the boot clock's seconds rounded up, read between two readings",
            )]),
        },
        Gap {
            status: Status::Pending(Arc::TimeTimersSchedIdentity),
            vehicles: &[
                Vehicle::Syscall,
                #[cfg(target_arch = "x86_64")]
                Vehicle::Raw,
            ],
            what: "sysinfo is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the syscall(2) and raw doors abort by name (the libc door reaches the shim's fixed sysinfo interposer, whose answers hold every relation)",
            failure: Failure::Stops {
                events: 0,
                ending: Ending::Signal(libc::SIGABRT),
                diagnostic: "patina: SUD trapped unsupported syscall sysinfo (nr",
            },
        },
    ],
    ..DEFAULTS
};
