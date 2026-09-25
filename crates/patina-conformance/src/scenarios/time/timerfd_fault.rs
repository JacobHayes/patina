//! time/timerfd_fault — timer descriptors handed pointers the kernel cannot
//! use (fs/timerfd.c): each is `EFAULT`, and what the call did before the
//! copy stands:
//!
//! * an unreadable new setting is `EFAULT` and arms nothing (it is copied
//!   in first);
//! * an unwritable old setting is `EFAULT` after the new one took;
//! * an unwritable current setting is `EFAULT`;
//! * a read into an unwritable buffer is `EFAULT` and has consumed the
//!   expirations (the count resets before `put_user`).
//!
//! Its own scenario, because a door that dereferences the pointer itself
//! ends the whole run (and a crash loses the captured event stream).

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Arm, Count, Probe, neg, spec_ns};
use crate::signals::PROGRESS_DEADLINE_NS;
use libc::*;
use patina_dst_syscalls::Syscall;

/// An address no mapping holds (the zero page).
const UNMAPPED: i64 = 1;

pub fn run(p: &Probe) {
    let fd = p.timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    p.require("create a nonblocking timerfd", fd >= 0);
    p.check(
        "an unreadable new setting is EFAULT",
        p.call_observed(
            Syscall::N_timerfd_settime,
            [fd as i64, 0, UNMAPPED, 0, 0, 0],
        ) == neg(EFAULT),
    );
    let (r, value, _) = p.timerfd_gettime(fd);
    p.check("and arms nothing", r == 0 && spec_ns(value) == 0);
    let later = itimerspec {
        it_interval: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: timespec {
            tv_sec: 100,
            tv_nsec: 0,
        },
    };
    p.check(
        "an unwritable old setting is EFAULT",
        p.call_observed(
            Syscall::N_timerfd_settime,
            [
                fd as i64,
                0,
                &later as *const itimerspec as i64,
                UNMAPPED,
                0,
                0,
            ],
        ) == neg(EFAULT),
    );
    let (r, value, _) = p.timerfd_gettime(fd);
    p.check("after the new setting took", r == 0 && spec_ns(value) > 0);
    p.check(
        "an unwritable current setting is EFAULT",
        p.call_observed(
            Syscall::N_timerfd_gettime,
            [fd as i64, UNMAPPED, 0, 0, 0, 0],
        ) == neg(EFAULT),
    );
    let (r, _, _) = p.timerfd_settime(fd, 0, Arm::Spec((0, 1_000_000)), (0, 0));
    p.check("arm it for a millisecond", r == 0);
    let (r, revents) = p.ppoll(&[(fd, POLLIN)], Some(PROGRESS_DEADLINE_NS));
    p.check("it expires", r == 1 && revents == [POLLIN]);
    p.check(
        "a read into an unwritable buffer is EFAULT",
        p.call_observed(Syscall::N_read, [fd as i64, UNMAPPED, 8, 0, 0, 0]) == neg(EFAULT),
    );
    p.check(
        "and has consumed the expiration",
        p.timerfd_read(fd, 8, Count::Exact).0 == neg(EAGAIN),
    );
    p.check("close the timerfd", p.close(fd) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/timerfd_fault",
    run,
    covers: &[
        Syscall::N_timerfd_create,
        Syscall::N_timerfd_settime,
        Syscall::N_timerfd_gettime,
    ],
    symbols: &["syscall", "read", "ppoll", "close"],
    ..DEFAULTS
};
