//! time/posix_timer — POSIX timers (kernel/time/posix-timers.c):
//!
//! * a `SIGEV_NONE` timer is created disarmed, arms, reads back its
//!   remaining time (lower by at least a sleep between two reads) and exact
//!   interval, re-arming answers the setting it
//!   replaces, and a zero value disarms it (answering the armed setting); a
//!   one-shot `SIGEV_NONE` timer that has expired reads back disarmed; it has
//!   no overrun;
//! * a `SIGEV_SIGNAL` timer's expiry is its signal with `SI_TIMER`, the
//!   timer's own id and the `sival_int` it was given; a one-shot timer has no
//!   overrun and is then disarmed; `TIMER_ABSTIME` with a past time fires at
//!   once, with a future clock reading at that time;
//! * a periodic timer whose signal stays pending counts overruns from its
//!   programmed expiry (`hrtimer_forward`): the dequeued signal's
//!   `si_overrun` and `timer_getoverrun` are at least the whole periods
//!   measured between arming and the dequeue, less the one the signal stands
//!   for (a longer wait only raises the count);
//! * a NULL `sevp` is `SIGALRM` carrying the timer id; `SIGEV_THREAD_ID`
//!   signals the named thread of the caller; the kernel takes `SIGEV_THREAD`
//!   (glibc builds its helper thread on `SIGEV_THREAD_ID`) as a signal; a
//!   process CPU-time timer reads back within what was set and fires once
//!   the process has computed past it (a bounded spin), then is disarmed;
//! * `EINVAL`: an unknown clock, an unknown `sigev_notify`, a signal 0 or
//!   past `SIGRTMAX`, a `SIGEV_THREAD_ID` naming no thread of the caller, a
//!   `tv_nsec` of a second (value) or a negative one (interval), and every
//!   row given an id the process never created or already deleted.
//!
//! Every signal stays blocked and is dequeued with a bounded
//! `rt_sigtimedwait`. Timer ids are the kernel's allocation, recorded by
//! relation; none is deleted before the last is created.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{
    Arm, Count, MISSING_PID, Probe, SIGSET_BYTES, Sigev, TimerId, ms, neg, spec_ns,
};
use crate::signals::{FIRST_RT, PROGRESS_DEADLINE, empty_set, gettid, has, set_of, spin_until};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

const SIG: i32 = FIRST_RT;
const VALUE: i32 = 0x5157;

fn wait_ns() -> i64 {
    PROGRESS_DEADLINE.as_nanos() as i64
}

/// Drain whatever of `set` is pending, unobserved (a periodic timer may have
/// fired again before it was disarmed).
fn drain(p: &Probe, set: &sigset_t) {
    p.rec
        .quiet(|| while p.timer_signal_wait(set, 0, false, Count::Exact).0 > 0 {});
}

pub fn run(p: &Probe) {
    let set = set_of(&[SIG, SIGALRM]);
    p.check(
        "block the timer signals",
        p.rt_sigprocmask(SIG_BLOCK, Some(&set), None, SIGSET_BYTES as usize) == 0,
    );

    let (r, quiet) = p.timer_create(CLOCK_MONOTONIC, Sigev::Quiet);
    p.require("create a SIGEV_NONE timer", r == 0);
    let (r, value, interval) = p.timer_gettime(quiet);
    p.check(
        "a new timer is disarmed",
        r == 0 && spec_ns(value) == 0 && spec_ns(interval) == 0,
    );
    let (r, old, _) = p.timer_settime(quiet, 0, Arm::Spec((5, 0)), ms(250));
    p.check(
        "arming answers the disarmed setting",
        r == 0 && spec_ns(old) == 0,
    );
    let (r, first, interval) = p.timer_gettime(quiet);
    p.check(
        "it reads back within what was set, the interval exact",
        r == 0 && spec_ns(first) > 0 && spec_ns(first) <= 5_000_000_000 && interval == ms(250),
    );
    p.check("sleep 2 ms", p.nanosleep(0, 2_000_000) == 0);
    let (r, second, _) = p.timer_gettime(quiet);
    p.check(
        "the remaining time dropped by at least the sleep",
        r == 0 && spec_ns(second) > 0 && spec_ns(second) <= spec_ns(first) - 2_000_000,
    );
    // Re-armed one-shot first: a zero value with a nonzero interval answers
    // differently across releases (6.8's common_timer_set clears the
    // interval before its zero-value return; 6.13+'s posix_timer_set_common
    // assigns the new interval first), so the scenario never disarms with a
    // nonzero interval.
    let (r, old, old_interval) = p.timer_settime(quiet, 0, Arm::Spec((5, 0)), (0, 0));
    p.check(
        "re-arming answers the periodic setting",
        r == 0 && spec_ns(old) > 0 && old_interval == ms(250),
    );
    let (r, old, old_interval) = p.timer_settime(quiet, 0, Arm::Spec((0, 0)), (0, 0));
    p.check(
        "a zero value disarms, answering the armed setting",
        r == 0 && spec_ns(old) > 0 && spec_ns(old_interval) == 0,
    );
    // What a SIGEV_NONE timer disarmed by a zero value reads back is not
    // asserted: 6.8's common_timer_get still computes it from the stale
    // expiry. A fresh one shows the expiry of a one-shot setting.
    let (r, once) = p.timer_create(CLOCK_MONOTONIC, Sigev::Quiet);
    p.require("create another SIGEV_NONE timer", r == 0);
    let (r, _, _) = p.timer_settime(once, 0, Arm::Spec(ms(1)), (0, 0));
    p.check("arm it for 1 ms", r == 0);
    p.check("sleep past it", p.nanosleep(0, 20_000_000) == 0);
    let (r, value, _) = p.timer_gettime(once);
    p.check(
        "an expired one-shot SIGEV_NONE timer reads back disarmed",
        r == 0 && spec_ns(value) == 0,
    );
    p.check(
        "a SIGEV_NONE timer has no overrun",
        p.timer_getoverrun(once, Count::Exact) == 0,
    );

    let (r, timer) = p.timer_create(
        CLOCK_MONOTONIC,
        Sigev::Signal {
            signo: SIG,
            value: VALUE,
        },
    );
    p.require("create a SIGEV_SIGNAL timer", r == 0);
    let (r, _, _) = p.timer_settime(timer, 0, Arm::Spec(ms(10)), (0, 0));
    p.check("arm it for 10 ms", r == 0);
    let (r, overrun) = p.timer_signal_wait(&set, wait_ns(), false, Count::Exact);
    p.check("its expiry is its signal", r == i64::from(SIG));
    p.check("a one-shot expiry has no overrun", overrun == 0);
    p.check(
        "timer_getoverrun agrees",
        p.timer_getoverrun(timer, Count::Exact) == 0,
    );
    let (r, value, _) = p.timer_gettime(timer);
    p.check(
        "an expired one-shot timer is disarmed",
        r == 0 && spec_ns(value) == 0,
    );

    // (0, 1) is long past natively; on a virtual monotonic clock that starts
    // at 0 it is past only because the sleeps above advanced it.
    let (r, _, _) = p.timer_settime(timer, TIMER_ABSTIME, Arm::Spec((0, 1)), (0, 0));
    p.check("arm it at an absolute time long past", r == 0);
    p.check(
        "it fires at once",
        p.timer_signal_wait(&set, wait_ns(), false, Count::Exact).0 == i64::from(SIG),
    );
    let (_, now) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    let at = now + 10_000_000;
    let (r, _, _) = p.timer_settime(
        timer,
        TIMER_ABSTIME,
        Arm::Reading(((at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64)),
        (0, 0),
    );
    p.check("arm it at an absolute time 10 ms ahead", r == 0);
    p.check(
        "it fires then",
        p.timer_signal_wait(&set, wait_ns(), false, Count::Exact).0 == i64::from(SIG),
    );

    let (r, _, _) = p.timer_settime(timer, 0, Arm::Spec(ms(1)), ms(1));
    p.check("arm it periodic at 1 ms", r == 0);
    let (_, armed_at) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    p.check(
        "sleep through twenty periods",
        p.nanosleep(0, 20_000_000) == 0,
    );
    // Every period from the programmed expiry up to the dequeue counts
    // (hrtimer_forward): the one the signal stands for, then overruns.
    let (_, before_dequeue) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    let bound = u64::try_from((before_dequeue - armed_at) / 1_000_000 - 1).unwrap_or(0);
    let (r, overrun) = p.timer_signal_wait(&set, wait_ns(), false, Count::AtLeast(bound));
    p.check("one signal is queued for them", r == i64::from(SIG));
    p.check(
        "the signal counts every period it stood for (at least 19 after 20 ms)",
        bound >= 19 && overrun as u64 >= bound,
    );
    p.check(
        "timer_getoverrun agrees",
        p.timer_getoverrun(timer, Count::AtLeast(bound)) as u64 >= bound,
    );
    let (r, old, old_interval) = p.timer_settime(timer, 0, Arm::Spec((5, 0)), (0, 0));
    p.check(
        "re-arming answers the periodic setting",
        r == 0 && spec_ns(old) > 0 && old_interval == ms(1),
    );
    let (r, _, _) = p.timer_settime(timer, 0, Arm::Spec((0, 0)), (0, 0));
    p.check("a zero value disarms it", r == 0);
    drain(p, &set);

    let (r, default) = p.timer_create(CLOCK_MONOTONIC, Sigev::Default);
    p.require("create a timer with a NULL sevp", r == 0);
    let (r, _, _) = p.timer_settime(default, 0, Arm::Spec(ms(10)), (0, 0));
    p.check("arm it for 10 ms", r == 0);
    p.check(
        "its expiry is SIGALRM carrying its id",
        p.timer_signal_wait(&set, wait_ns(), true, Count::Exact).0 == i64::from(SIGALRM),
    );

    let tid = gettid();
    let (r, directed) = p.timer_create(
        CLOCK_MONOTONIC,
        Sigev::ThreadId {
            signo: SIG,
            value: VALUE + 1,
            tid,
            own: true,
        },
    );
    p.require("create a SIGEV_THREAD_ID timer for this thread", r == 0);
    let (r, _, _) = p.timer_settime(directed, 0, Arm::Spec(ms(10)), (0, 0));
    p.check("arm it for 10 ms", r == 0);
    p.check(
        "its expiry is its signal, to this thread",
        p.timer_signal_wait(&set, wait_ns(), false, Count::Exact).0 == i64::from(SIG),
    );

    let (r, thread) = p.timer_create(
        CLOCK_MONOTONIC,
        Sigev::Thread {
            signo: SIG,
            value: VALUE + 2,
        },
    );
    p.check("the kernel takes SIGEV_THREAD as a signal", r == 0);
    let (r, cpu) = p.timer_create(
        CLOCK_PROCESS_CPUTIME_ID,
        Sigev::Signal {
            signo: SIG,
            value: VALUE + 3,
        },
    );
    p.require("a process CPU-time clock takes a timer", r == 0);
    let (r, _, _) = p.timer_settime(cpu, 0, Arm::Spec(ms(1)), (0, 0));
    let (_, value, _) = p.timer_gettime(cpu);
    p.check(
        "it arms and reads back within what was set",
        r == 0 && spec_ns(value) > 0 && spec_ns(value) <= 1_000_000,
    );
    let pending = spin_until(|| {
        let mut pending = empty_set();
        p.rec
            .quiet(|| p.rt_sigpending(&mut pending, SIGSET_BYTES as usize))
            == 0
            && has(&pending, SIG)
    });
    p.mark("spin", &[("fired", Value::from(pending))]);
    let (r, overrun) = p.timer_signal_wait(&set, 0, false, Count::Exact);
    p.check(
        "computing past it fires its signal",
        r == i64::from(SIG) && overrun == 0,
    );
    let (r, value, _) = p.timer_gettime(cpu);
    p.check(
        "the fired one-shot timer is disarmed",
        r == 0 && spec_ns(value) == 0,
    );

    p.check(
        "an unknown clock is EINVAL",
        p.timer_create(1234, Sigev::Quiet).0 == neg(EINVAL),
    );
    p.check(
        "an unknown sigev_notify is EINVAL",
        p.timer_create(CLOCK_MONOTONIC, Sigev::Unknown(99)).0 == neg(EINVAL),
    );
    p.check(
        "signal 0 is EINVAL",
        p.timer_create(CLOCK_MONOTONIC, Sigev::Signal { signo: 0, value: 0 })
            .0
            == neg(EINVAL),
    );
    p.check(
        "a signal past SIGRTMAX is EINVAL",
        p.timer_create(
            CLOCK_MONOTONIC,
            Sigev::Signal {
                signo: 65,
                value: 0,
            },
        )
        .0 == neg(EINVAL),
    );
    p.check(
        "SIGEV_THREAD_ID naming no thread of the caller is EINVAL",
        p.timer_create(
            CLOCK_MONOTONIC,
            Sigev::ThreadId {
                signo: SIG,
                value: 0,
                tid: MISSING_PID,
                own: false,
            },
        )
        .0 == neg(EINVAL),
    );
    p.check(
        "a tv_nsec of a second is EINVAL",
        p.timer_settime(quiet, 0, Arm::Spec((0, 1_000_000_000)), (0, 0))
            .0
            == neg(EINVAL),
    );
    p.check(
        "a negative interval tv_nsec is EINVAL",
        p.timer_settime(quiet, 0, Arm::Spec(ms(10)), (0, -1)).0 == neg(EINVAL),
    );
    let missing = TimerId::unallocated(0x7fff_0000);
    p.check(
        "timer_settime of an id never created is EINVAL",
        p.timer_settime(missing, 0, Arm::Spec(ms(10)), (0, 0)).0 == neg(EINVAL),
    );
    p.check(
        "timer_gettime of it is EINVAL",
        p.timer_gettime(missing).0 == neg(EINVAL),
    );
    p.check(
        "timer_getoverrun of it is EINVAL",
        p.timer_getoverrun(missing, Count::Exact) == neg(EINVAL),
    );
    p.check(
        "timer_delete of it is EINVAL",
        p.timer_delete(missing) == neg(EINVAL),
    );

    for id in [quiet, once, timer, default, directed, thread, cpu] {
        p.check("delete the timer", p.timer_delete(id) == 0);
    }
    p.check(
        "a deleted timer is EINVAL to delete",
        p.timer_delete(timer) == neg(EINVAL),
    );
    p.check("and to read", p.timer_gettime(timer).0 == neg(EINVAL));
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/posix_timer",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_timer_create,
        Syscall::N_timer_settime,
        Syscall::N_timer_gettime,
        Syscall::N_timer_getoverrun,
        Syscall::N_timer_delete,
    ],
    ..DEFAULTS
};
