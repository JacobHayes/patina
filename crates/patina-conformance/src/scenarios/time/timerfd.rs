//! time/timerfd — timer descriptors (fs/timerfd.c):
//!
//! * `TFD_NONBLOCK | TFD_CLOEXEC` set the descriptor's flags; a new timer is
//!   disarmed; reading an unexpired timer is `EAGAIN` nonblocking, and a
//!   buffer shorter than a `u64` is `EINVAL`;
//! * arming answers the old setting; reading it back answers the remaining
//!   time (lower by at least a sleep between two reads) and the exact
//!   interval; the descriptor turns readable at expiry (`ppoll`), and a read
//!   answers the expirations since the last read as one `u64` (exactly 1 for
//!   a one-shot timer) and resets them;
//! * a periodic timer counts every period from its programmed expiry: at
//!   least the whole periods measured between arming and the read (a longer
//!   wait only raises the count); it reads back at most its interval (0 the
//!   moment a period ends, until the interrupt forwards it —
//!   `timerfd_get_remaining` — so armed-ness is its interval); a zero value
//!   disarms it, answering the periodic setting, and drops the unread count;
//! * `TFD_TIMER_ABSTIME` with a past time turns readable at once (waited on
//!   with `ppoll`: the expiry is an interrupt, not the syscall), once;
//! * a blocking read waits for the expiry; `TFD_TIMER_CANCEL_ON_SET` on an
//!   absolute `CLOCK_REALTIME` timer changes nothing while nobody sets the
//!   clock (the read answers the expiry, not `ECANCELED`, which only a clock
//!   set produces — a privileged act this scenario never performs), and is
//!   accepted on a relative timer too;
//! * `EINVAL`: a clock timerfd does not take (a CPU-time clock, an unknown
//!   id), an unknown create or settime flag, a `tv_nsec` of a second, and a
//!   descriptor that is not a timer (a pipe); a closed descriptor is `EBADF`.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Arm, Count, Probe, ms, neg, spec_ns};
use crate::signals::PROGRESS_DEADLINE;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

fn wait_ns() -> i64 {
    PROGRESS_DEADLINE.as_nanos() as i64
}

pub fn run(p: &Probe) {
    let fd = p.timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    p.require("create a nonblocking timerfd", fd >= 0);
    p.check(
        "TFD_CLOEXEC sets FD_CLOEXEC",
        p.fcntl(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    p.check(
        "TFD_NONBLOCK sets O_NONBLOCK",
        p.fcntl(fd, F_GETFL, 0) & i64::from(O_NONBLOCK) != 0,
    );
    let (r, value, interval) = p.timerfd_gettime(fd);
    p.check(
        "a new timer is disarmed",
        r == 0 && spec_ns(value) == 0 && spec_ns(interval) == 0,
    );
    p.check(
        "reading an unexpired timer is EAGAIN",
        p.timerfd_read(fd, 8, Count::Exact).0 == neg(EAGAIN),
    );
    p.check(
        "a buffer shorter than a u64 is EINVAL",
        p.timerfd_read(fd, 4, Count::Exact).0 == neg(EINVAL),
    );

    let (r, old, _) = p.timerfd_settime(fd, 0, Arm::Spec((5, 0)), (0, 0));
    p.check(
        "arming answers the disarmed setting",
        r == 0 && spec_ns(old) == 0,
    );
    let (r, first, interval) = p.timerfd_gettime(fd);
    p.check(
        "it reads back within what was set",
        r == 0 && spec_ns(first) > 0 && spec_ns(first) <= 5_000_000_000 && spec_ns(interval) == 0,
    );
    p.check("sleep 2 ms", p.nanosleep(0, 2_000_000) == 0);
    let (r, second, _) = p.timerfd_gettime(fd);
    p.check(
        "the remaining time dropped by at least the sleep",
        r == 0 && spec_ns(second) <= spec_ns(first) - 2_000_000,
    );
    let (r, old, _) = p.timerfd_settime(fd, 0, Arm::Spec(ms(10)), (0, 0));
    p.check(
        "re-arming for 10 ms answers the armed setting",
        r == 0 && spec_ns(old) > 0 && spec_ns(old) <= spec_ns(second),
    );
    let (r, revents) = p.ppoll(&[(fd, POLLIN)], Some(wait_ns()));
    p.check("it turns readable at expiry", r == 1 && revents == [POLLIN]);
    let (r, count) = p.timerfd_read(fd, 8, Count::Exact);
    p.check("a read answers one expiration", r == 8 && count == 1);
    p.check(
        "and resets the count",
        p.timerfd_read(fd, 8, Count::Exact).0 == neg(EAGAIN),
    );
    let (r, value, _) = p.timerfd_gettime(fd);
    p.check(
        "an expired one-shot timer is disarmed",
        r == 0 && spec_ns(value) == 0,
    );

    let (r, _, _) = p.timerfd_settime(fd, 0, Arm::Spec(ms(1)), ms(1));
    p.check("arm it periodic at 1 ms", r == 0);
    let (_, armed_at) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    p.check(
        "sleep through twenty periods",
        p.nanosleep(0, 20_000_000) == 0,
    );
    // Every period from the programmed expiry up to the read counts
    // (hrtimer_forward_now), so the whole periods measured between arming
    // and the read are a lower bound.
    let (_, before_read) = p.rec.quiet(|| p.clock_gettime(CLOCK_MONOTONIC));
    let bound = u64::try_from((before_read - armed_at) / 1_000_000).unwrap_or(0);
    let (r, count) = p.timerfd_read(fd, 8, Count::AtLeast(bound));
    p.check(
        "a read answers every period (at least 20 after 20 ms)",
        r == 8 && bound >= 20 && count >= bound,
    );
    // A periodic timerfd answers 0 remaining the moment a period ends,
    // until its interrupt forwards it: armed-ness is its interval.
    let (r, value, interval) = p.timerfd_gettime(fd);
    p.check(
        "a periodic timer stays armed within its interval",
        r == 0 && spec_ns(value) <= 1_000_000 && interval == ms(1),
    );
    let (r, _, old_interval) = p.timerfd_settime(fd, 0, Arm::Spec((0, 0)), (0, 0));
    p.check(
        "a zero value disarms, answering the periodic setting",
        r == 0 && old_interval == ms(1),
    );
    p.check(
        "and drops the unread count",
        p.timerfd_read(fd, 8, Count::Exact).0 == neg(EAGAIN),
    );

    // (0, 1) is long past natively; on a virtual monotonic clock that starts
    // at 0 it is past only because the sleeps above advanced it.
    let (r, _, _) = p.timerfd_settime(fd, TFD_TIMER_ABSTIME, Arm::Spec((0, 1)), (0, 0));
    p.check("arm it at an absolute time long past", r == 0);
    let (r, revents) = p.ppoll(&[(fd, POLLIN)], Some(wait_ns()));
    p.check("it turns readable", r == 1 && revents == [POLLIN]);
    let (r, count) = p.timerfd_read(fd, 8, Count::Exact);
    p.check("it expired at once, once", r == 8 && count == 1);

    let blocking = p.timerfd_create(CLOCK_REALTIME, 0);
    p.require("create a blocking CLOCK_REALTIME timerfd", blocking >= 0);
    let (_, now) = p.rec.quiet(|| p.clock_gettime(CLOCK_REALTIME));
    let at = now + 10_000_000;
    let (r, _, _) = p.timerfd_settime(
        blocking,
        TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
        Arm::Reading(((at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64)),
        (0, 0),
    );
    p.check("arm it absolute, cancelled on a clock set", r == 0);
    let (r, count) = p.timerfd_read(blocking, 8, Count::Exact);
    p.check(
        "a blocking read waits for the expiry, not ECANCELED",
        r == 8 && count == 1,
    );
    let (r, _, _) = p.timerfd_settime(blocking, TFD_TIMER_CANCEL_ON_SET, Arm::Spec(ms(10)), (0, 0));
    p.check(
        "TFD_TIMER_CANCEL_ON_SET is accepted on a relative timer",
        r == 0,
    );
    let (r, count) = p.timerfd_read(blocking, 8, Count::Exact);
    p.check("which expires as armed", r == 8 && count == 1);

    let boot = p.timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK);
    p.check("CLOCK_BOOTTIME takes a timerfd", boot >= 0);
    p.check(
        "a CPU-time clock is EINVAL",
        p.timerfd_create(CLOCK_PROCESS_CPUTIME_ID, 0) == neg(EINVAL) as i32,
    );
    p.check(
        "an unknown clock is EINVAL",
        p.timerfd_create(1234, 0) == neg(EINVAL) as i32,
    );
    p.check(
        "an unknown create flag is EINVAL",
        p.timerfd_create(CLOCK_MONOTONIC, 1) == neg(EINVAL) as i32,
    );
    p.check(
        "an unknown settime flag is EINVAL",
        p.timerfd_settime(fd, 4, Arm::Spec(ms(10)), (0, 0)).0 == neg(EINVAL),
    );
    p.check(
        "a tv_nsec of a second is EINVAL",
        p.timerfd_settime(fd, 0, Arm::Spec((0, 1_000_000_000)), (0, 0))
            .0
            == neg(EINVAL),
    );
    let (r, pipe) = p.pipe2(O_CLOEXEC);
    p.require("a pipe", r == 0);
    p.check(
        "timerfd_settime of a pipe is EINVAL",
        p.timerfd_settime(pipe[0], 0, Arm::Spec(ms(10)), (0, 0)).0 == neg(EINVAL),
    );
    p.check(
        "timerfd_gettime of a pipe is EINVAL",
        p.timerfd_gettime(pipe[0]).0 == neg(EINVAL),
    );
    for descriptor in [pipe[0], pipe[1], blocking, boot] {
        p.close(descriptor);
    }
    p.check("close the timerfd", p.close(fd) == 0);
    p.check(
        "timerfd_gettime of a closed descriptor is EBADF",
        p.timerfd_gettime(fd).0 == neg(EBADF),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/timerfd",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_timerfd_create,
        Syscall::N_timerfd_settime,
        Syscall::N_timerfd_gettime,
    ],
    ..DEFAULTS
};
