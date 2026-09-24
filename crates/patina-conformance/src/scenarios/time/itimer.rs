//! time/itimer — the interval timers (kernel/time/itimer.c):
//!
//! * `ITIMER_REAL` starts disarmed; arming answers the old timer; reading it
//!   back answers the remaining time (within what was set, and lower by at
//!   least a sleep between two reads: `nanosleep` never returns early) and
//!   the interval exactly as set; a zero `it_value` disarms and drops the
//!   interval;
//! * expiry sends `SIGALRM` (`SI_KERNEL`); a one-shot timer is then
//!   disarmed; a periodic one reloads from its interval, fires again and
//!   stays armed;
//! * an unknown `which`, a `tv_usec` of a second or a negative one (value or
//!   interval) is `EINVAL`;
//! * the CPU-time timers (`ITIMER_VIRTUAL`, `ITIMER_PROF`) arm, read back
//!   and disarm; the kernel adds one tick to their first expiry
//!   (`set_cpu_itimer`), so what reads back is within the set value plus a
//!   tick; a 10 ms one fires (`SIGVTALRM`/`SIGPROF`, `SI_KERNEL`) once the
//!   process has computed past it — a bounded spin, since CPU time accrues
//!   only while it runs — and is then disarmed;
//! * (x86_64) `alarm` answers the previous alarm's remaining seconds rounded
//!   to the nearest, a nonzero remainder under a second rounding up to 1
//!   (`alarm_setitimer`); it is `ITIMER_REAL`; `alarm(0)` cancels; its expiry
//!   is `SIGALRM`.
//!
//! `SIGALRM` stays blocked, so every expiry is dequeued with a bounded
//! `rt_sigtimedwait` — a wait that ends the moment the signal is pending,
//! never a timing assertion. The generic (arm64) table has no `alarm` row
//! (glibc spells it `setitimer`), so that section is x86_64-only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, SIGSET_BYTES, micros, ms_us, neg};
use crate::signals::{PROGRESS_DEADLINE, empty_set, has, one_set, set_of, spin_until};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// One tick at the lowest `CONFIG_HZ` the kernel offers (100).
const TICK_US: i64 = 10_000;

fn wait_ns() -> i64 {
    PROGRESS_DEADLINE.as_nanos() as i64
}

/// Dequeue one pending `SIGALRM` within the progress deadline.
fn alarm_expires(p: &Probe, set: &sigset_t, label: &str) {
    // SAFETY: all-zero is a valid siginfo_t.
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    let r = p.rt_sigtimedwait(set, Some(&mut info), Some(wait_ns()), SIGSET_BYTES as usize);
    p.check(
        label,
        r == i64::from(SIGALRM) && info.si_code == crate::probe::SI_KERNEL,
    );
}

pub fn run(p: &Probe) {
    let alrm = one_set(SIGALRM);
    p.check(
        "block SIGALRM",
        p.rt_sigprocmask(SIG_BLOCK, Some(&alrm), None, SIGSET_BYTES as usize) == 0,
    );

    let (r, value, interval) = p.getitimer(ITIMER_REAL);
    p.check(
        "ITIMER_REAL starts disarmed",
        r == 0 && micros(value) == 0 && micros(interval) == 0,
    );
    let (r, old, _) = p.setitimer(ITIMER_REAL, (5, 0), (0, 0));
    p.check(
        "arming answers the old, disarmed timer",
        r == 0 && micros(old) == 0,
    );
    let (r, first, interval) = p.getitimer(ITIMER_REAL);
    p.check(
        "the remaining time is within what was set",
        r == 0 && micros(first) > 0 && micros(first) <= 5_000_000 && micros(interval) == 0,
    );
    p.check("sleep 2 ms", p.nanosleep(0, 2_000_000) == 0);
    let (r, second, _) = p.getitimer(ITIMER_REAL);
    p.check(
        "the remaining time dropped by at least the sleep",
        r == 0 && micros(second) > 0 && micros(second) <= micros(first) - 2_000,
    );
    let (r, old, _) = p.setitimer(ITIMER_REAL, (0, 0), (0, 0));
    p.check(
        "a zero value disarms, answering the armed timer",
        r == 0 && micros(old) > 0 && micros(old) <= micros(second),
    );
    let (r, value, _) = p.getitimer(ITIMER_REAL);
    p.check("it is disarmed", r == 0 && micros(value) == 0);
    let (r, _, _) = p.setitimer(ITIMER_REAL, (0, 0), ms_us(10));
    let (_, value, interval) = p.getitimer(ITIMER_REAL);
    p.check(
        "a zero value with an interval stays disarmed and drops the interval",
        r == 0 && micros(value) == 0 && micros(interval) == 0,
    );

    let (r, _, _) = p.setitimer(ITIMER_REAL, ms_us(10), (0, 0));
    p.check("arm a 10 ms one-shot timer", r == 0);
    alarm_expires(p, &alrm, "its expiry is SIGALRM from the kernel");
    let (r, value, _) = p.getitimer(ITIMER_REAL);
    p.check(
        "an expired one-shot timer is disarmed",
        r == 0 && micros(value) == 0,
    );

    let (r, _, _) = p.setitimer(ITIMER_REAL, ms_us(10), ms_us(10));
    p.check("arm a 10 ms periodic timer", r == 0);
    alarm_expires(p, &alrm, "its first expiry is SIGALRM");
    alarm_expires(p, &alrm, "it reloads from its interval and fires again");
    let (r, value, interval) = p.getitimer(ITIMER_REAL);
    p.check(
        "a periodic timer stays armed within its interval",
        r == 0 && micros(value) > 0 && micros(value) <= 10_000 && interval == ms_us(10),
    );
    let (r, old, old_interval) = p.setitimer(ITIMER_REAL, (0, 0), (0, 0));
    p.check(
        "disarming answers the periodic timer",
        r == 0 && micros(old) > 0 && old_interval == ms_us(10),
    );
    // A period may have ended between the read and the disarm: drain it,
    // unobserved (whether one did is the host's scheduling).
    p.rec.quiet(|| {
        // SAFETY: all-zero is a valid siginfo_t.
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        p.rt_sigtimedwait(&alrm, Some(&mut info), Some(0), SIGSET_BYTES as usize)
    });

    p.check(
        "an unknown which is EINVAL",
        p.setitimer(5, ms_us(10), (0, 0)).0 == neg(EINVAL),
    );
    p.check(
        "getitimer of an unknown which is EINVAL",
        p.getitimer(5).0 == neg(EINVAL),
    );
    p.check(
        "a tv_usec of a second is EINVAL",
        p.setitimer(ITIMER_REAL, (0, 1_000_000), (0, 0)).0 == neg(EINVAL),
    );
    p.check(
        "a negative tv_usec is EINVAL",
        p.setitimer(ITIMER_REAL, (0, -1), (0, 0)).0 == neg(EINVAL),
    );
    p.check(
        "an interval's tv_usec of a second is EINVAL",
        p.setitimer(ITIMER_REAL, ms_us(10), (0, 1_000_000)).0 == neg(EINVAL),
    );
    let (_, value, _) = p.getitimer(ITIMER_REAL);
    p.check(
        "a refused arming leaves the timer disarmed",
        micros(value) == 0,
    );

    for which in [ITIMER_VIRTUAL, ITIMER_PROF] {
        let (r, old, _) = p.setitimer(which, (1, 0), (0, 500_000));
        p.check("a CPU-time timer arms", r == 0 && micros(old) == 0);
        let (r, value, interval) = p.getitimer(which);
        p.check(
            "it reads back within the set value and a tick, its interval exact",
            r == 0
                && micros(value) > 0
                && micros(value) <= 1_000_000 + TICK_US
                && interval == (0, 500_000),
        );
        let (r, old, _) = p.setitimer(which, (0, 0), (0, 0));
        p.check("it disarms", r == 0 && micros(old) > 0);
    }

    let cpu_signals = set_of(&[SIGVTALRM, SIGPROF]);
    p.check(
        "block SIGVTALRM and SIGPROF",
        p.rt_sigprocmask(SIG_BLOCK, Some(&cpu_signals), None, SIGSET_BYTES as usize) == 0,
    );
    for (which, sig) in [(ITIMER_VIRTUAL, SIGVTALRM), (ITIMER_PROF, SIGPROF)] {
        let (r, _, _) = p.setitimer(which, ms_us(10), (0, 0));
        p.check("arm a CPU-time timer for 10 ms", r == 0);
        let pending = spin_until(|| {
            let mut set = empty_set();
            p.rec
                .quiet(|| p.rt_sigpending(&mut set, SIGSET_BYTES as usize))
                == 0
                && has(&set, sig)
        });
        p.mark("spin", &[("fired", Value::from(pending))]);
        // SAFETY: all-zero is a valid siginfo_t.
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        let r = p.rt_sigtimedwait(
            &one_set(sig),
            Some(&mut info),
            Some(0),
            SIGSET_BYTES as usize,
        );
        p.check(
            "computing past it fires its signal from the kernel",
            r == i64::from(sig) && info.si_code == crate::probe::SI_KERNEL,
        );
        let (r, value, _) = p.getitimer(which);
        p.check(
            "the fired one-shot timer is disarmed",
            r == 0 && micros(value) == 0,
        );
    }

    #[cfg(target_arch = "x86_64")]
    {
        p.check("alarm with none pending answers 0", p.alarm(10, &[]) == 0);
        // Documented answers for a stall under 1.5 s between the two calls
        // (the remainder rounds to the nearest second).
        let previous = p.alarm(3, &["9", "10"]);
        p.check(
            "alarm answers the previous alarm's seconds, rounded",
            previous == 10 || previous == 9,
        );
        let (r, value, _) = p.getitimer(ITIMER_REAL);
        p.check(
            "an alarm is ITIMER_REAL",
            r == 0 && micros(value) > 0 && micros(value) <= 3_000_000,
        );
        // Holds for a stall under 0.9 s between the arming and the alarm.
        let (r, _, _) = p.setitimer(ITIMER_REAL, ms_us(900), (0, 0));
        p.check("arm 900 ms", r == 0);
        p.check(
            "a sub-second remainder rounds up to one second",
            p.alarm(0, &[]) == 1,
        );
        p.check("alarm(0) cancelled it", p.alarm(0, &[]) == 0);
        p.check("an alarm of one second", p.alarm(1, &[]) == 0);
        alarm_expires(p, &alrm, "the alarm's expiry is SIGALRM");
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/itimer",
    run,
    covers: &[
        Syscall::N_setitimer,
        Syscall::N_getitimer,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_alarm,
    ],
    symbols: &["syscall", "nanosleep", "clock_gettime"],
    ..DEFAULTS
};
