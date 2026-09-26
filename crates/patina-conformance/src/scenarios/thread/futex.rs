//! thread/futex — the futex row behind std's locks and parking: value
//! mismatch (private and shared), wake with no waiters, a timed wait on the clock, an unknown op,
//! an empty bitset, a requeue, and a real handshake with a second thread (the racy loop is
//! unobserved; the outcome is).

use crate::catalog::{DEFAULTS, Scenario, TraceFacts};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::{FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE, Probe, neg};
use libc::*;
use std::sync::atomic::{AtomicU32, Ordering};

pub fn run(p: &Probe) {
    let word = AtomicU32::new(0);
    p.check(
        "FUTEX_WAIT with a stale expected value is EAGAIN",
        p.futex(&word, FUTEX_WAIT_PRIVATE, 1, None) == neg(EAGAIN),
    );
    p.check(
        "a shared (not private) FUTEX_WAIT with a stale value is EAGAIN too",
        p.futex(&word, FUTEX_WAIT, 1, None) == neg(EAGAIN),
    );
    p.check(
        "FUTEX_WAKE with no waiters wakes 0",
        p.futex(&word, FUTEX_WAKE_PRIVATE, 1, None) == 0,
    );
    let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
    p.check(
        "a timed FUTEX_WAIT nobody wakes is ETIMEDOUT",
        p.futex(&word, FUTEX_WAIT_PRIVATE, 0, Some(1_000_000)) == neg(ETIMEDOUT),
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
    // The probe passes 0 as `val3`: an empty bitset, and a requeue's `cmpval`.
    p.check(
        "FUTEX_WAIT_BITSET with an empty bitset is EINVAL",
        p.futex(&word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, None) == neg(EINVAL),
    );
    p.check(
        "and so is FUTEX_WAKE_BITSET",
        p.futex(&word, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, None) == neg(EINVAL),
    );
    p.check(
        "FUTEX_REQUEUE with nobody queued moves nobody",
        p.futex(&word, FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG, 1, None) == 0,
    );

    std::thread::scope(|scope| {
        scope.spawn(|| {
            p.rec.quiet(|| {
                while word.load(Ordering::SeqCst) == 0 {
                    p.futex(&word, FUTEX_WAIT_PRIVATE, 0, None);
                }
            });
            word.store(2, Ordering::SeqCst);
            p.rec.quiet(|| p.futex(&word, FUTEX_WAKE_PRIVATE, 1, None));
        });
        word.store(1, Ordering::SeqCst);
        p.rec.quiet(|| {
            while word.load(Ordering::SeqCst) != 2 {
                p.futex(&word, FUTEX_WAKE_PRIVATE, 1, None);
                p.futex(&word, FUTEX_WAIT_PRIVATE, 1, Some(1_000_000));
            }
        });
    });
    p.check(
        "the second thread observed 1 and answered 2",
        word.load(Ordering::SeqCst) == 2,
    );
    p.check(
        "a final FUTEX_WAKE finds nobody",
        p.futex(&word, FUTEX_WAKE_PRIVATE, i32::MAX as u32, None) == 0,
    );
    p.check(
        "FUTEX_CMP_REQUEUE of a word that no longer holds cmpval is EAGAIN",
        p.futex(&word, FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG, 1, None) == neg(EAGAIN),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/futex",
    run,
    // Every row's libc spelling is glibc's syscall(2): a libc leg would
    // repeat the syscall one.
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_futex, Syscall::N_clock_gettime],
    trace: Some(TraceFacts {
        generations: &[],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
