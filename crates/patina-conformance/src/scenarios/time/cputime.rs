//! time/cputime — process CPU time (`times`, `getrusage`; kernel/sys.c,
//! kernel/sched/cputime.c):
//!
//! * `times` answers clock ticks since an arbitrary point (recorded by its
//!   order relation), with or without a buffer; a freshly forked process
//!   (the harness forks the probe itself) has no children's time;
//! * the clock ticks are `sysconf(_SC_CLK_TCK)` = `USER_HZ` = 100 per second
//!   on both targets (a kernel ABI constant, not the host's `CONFIG_HZ`);
//! * a process that has run has used CPU time: `getrusage(RUSAGE_SELF)` is
//!   positive from the start (`cputime_adjust` makes user + system time the
//!   scheduler's runtime, which the startup alone puts far past a
//!   microsecond); it never decreases; `RUSAGE_THREAD` of the only thread
//!   never exceeds `RUSAGE_SELF` read after it (each is truncated to whole
//!   microseconds in two parts, so within 2 µs); the process CPU clock read
//!   after is at least `RUSAGE_SELF`; `RUSAGE_CHILDREN` is all zero; an
//!   unknown `who` is `EINVAL`;
//! * computing advances all three: after a spin that consumes at least 20 ms
//!   of CPU (bounded; a loaded host only makes it take longer), the process
//!   CPU clock advanced by that, `getrusage` by at least 19 ms, and `times`
//!   by at least one tick.
//!
//! How much CPU time the process has used is the host's business: every
//! figure is related, never recorded.
//!
//! Under patina the first reading is the virtual kernel's modeled startup
//! cost (`patina_dst_abi::STARTUP_CPU_NANOS`), and the spin advances CPU time
//! through the runtime's advance-on-spin rescue.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::signals::spin_until;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// The CPU time the spin consumes.
const SPIN_NS: i128 = 20_000_000;

pub fn run(p: &Probe) {
    let (r, first) = p.times(false);
    p.check("times answers", r >= 0);
    p.check(
        "a freshly forked process has no children's time",
        first.cutime == 0 && first.cstime == 0,
    );
    p.check("times with a NULL buffer answers", p.times(true).0 >= 0);
    // SAFETY: sysconf reads a constant.
    let hz = unsafe { sysconf(_SC_CLK_TCK) };
    p.mark(
        "sysconf",
        &[
            ("name", Value::from("_SC_CLK_TCK")),
            ("value", Value::from(hz)),
        ],
    );
    p.check("clock ticks are USER_HZ, 100 per second", hz == 100);

    let (r, self_before) = p.getrusage(RUSAGE_SELF);
    p.check(
        "a process that has run has used CPU time",
        r == 0 && self_before.cpu_us > 0,
    );
    let (r, thread) = p.getrusage(RUSAGE_THREAD);
    p.check("getrusage RUSAGE_THREAD", r == 0);
    let (r, self_after) = p.getrusage(RUSAGE_SELF);
    p.check("getrusage RUSAGE_SELF again", r == 0);
    p.check(
        "the process's CPU time never decreases",
        self_after.cpu_us >= self_before.cpu_us,
    );
    p.check(
        "the only thread's time is within the process's",
        thread.cpu_us <= self_after.cpu_us + 2,
    );
    let (r, cpu_before) = p.clock_gettime(CLOCK_PROCESS_CPUTIME_ID);
    p.check(
        "the process CPU clock read after is at least getrusage's figure",
        r == 0 && cpu_before / 1000 >= i128::from(self_after.cpu_us),
    );
    let (r, children) = p.getrusage(RUSAGE_CHILDREN);
    p.check("RUSAGE_CHILDREN is all zero", r == 0 && children.all_zero);
    p.check("an unknown who is EINVAL", p.getrusage(5).0 == neg(EINVAL));

    let spun = spin_until(|| {
        let (r, now) = p.rec.quiet(|| p.clock_gettime(CLOCK_PROCESS_CPUTIME_ID));
        r == 0 && now - cpu_before >= SPIN_NS
    });
    p.mark("spin", &[("consumed_20ms", Value::from(spun))]);
    let (r, cpu_after) = p.clock_gettime(CLOCK_PROCESS_CPUTIME_ID);
    p.check(
        "computing advances the process CPU clock",
        r == 0 && cpu_after - cpu_before >= SPIN_NS,
    );
    let (r, self_spun) = p.getrusage(RUSAGE_SELF);
    p.check(
        "and getrusage by at least 19 ms",
        r == 0 && self_spun.cpu_us - self_after.cpu_us >= 19_000,
    );
    let (r, last) = p.times(false);
    p.check(
        "and times by at least one tick",
        r >= 0 && (last.utime + last.stime) - (first.utime + first.stime) >= 1,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/cputime",
    run,
    covers: &[Syscall::N_times, Syscall::N_getrusage],
    symbols: &["syscall", "getrusage", "sysconf", "clock_gettime"],
    ..DEFAULTS
};
