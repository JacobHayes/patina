//! thread/futex — the futex row behind std's locks and parking: value
//! mismatch, wake with no waiters, a timed wait on the clock, an unknown op,
//! and a real handshake with a second thread (the racy loop is unobserved; the
//! outcome is).

use crate::catalog::{DEFAULTS, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;
use std::sync::atomic::{AtomicU32, Ordering};

const WAIT: i32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const WAKE: i32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

pub fn run(p: &Probe) {
    let word = AtomicU32::new(0);
    p.check(
        "FUTEX_WAIT with a stale expected value is EAGAIN",
        p.futex(&word, WAIT, 1, None) == neg(EAGAIN),
    );
    p.check(
        "FUTEX_WAKE with no waiters wakes 0",
        p.futex(&word, WAKE, 1, None) == 0,
    );
    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "a timed FUTEX_WAIT nobody wakes is ETIMEDOUT",
        p.futex(&word, WAIT, 0, Some(1_000_000)) == neg(ETIMEDOUT),
    );
    let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "the timed wait advanced the clock by at least the timeout",
        after - before >= 1_000_000,
    );
    p.check(
        "an unknown futex op is ENOSYS",
        p.futex(&word, 999, 0, None) == neg(ENOSYS),
    );

    std::thread::scope(|scope| {
        scope.spawn(|| {
            p.rec.quiet(|| {
                while word.load(Ordering::SeqCst) == 0 {
                    p.futex(&word, WAIT, 0, None);
                }
            });
            word.store(2, Ordering::SeqCst);
            p.rec.quiet(|| p.futex(&word, WAKE, 1, None));
        });
        word.store(1, Ordering::SeqCst);
        p.rec.quiet(|| {
            while word.load(Ordering::SeqCst) != 2 {
                p.futex(&word, WAKE, 1, None);
                p.futex(&word, WAIT, 1, Some(1_000_000));
            }
        });
    });
    p.check(
        "the second thread observed 1 and answered 2",
        word.load(Ordering::SeqCst) == 2,
    );
    p.check(
        "a final FUTEX_WAKE finds nobody",
        p.futex(&word, WAKE, i32::MAX as u32, None) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/futex",
    run,
    covers: &[Syscall::N_futex, Syscall::N_clock_gettime],
    symbols: &["syscall", "clock_gettime"],
    trace: Some(TraceFacts {
        generations: &[],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
