//! thread/futex2 — the futex2 rows (Linux 5.16 `futex_waitv`, 6.7
//! `futex_wake`, `futex_wait` and `futex_requeue`; kernel/futex/syscalls.c),
//! as 6.8 judges them:
//!
//! * the flags name a size and scope, and only a 32-bit word is implemented
//!   (`futex_flags_valid`): an 8-bit or 64-bit size, or an unknown flag, is
//!   `EINVAL`, as is a misaligned word;
//! * the bitset and the value must fit the size (`futex_validate_input`),
//!   and a bitset is never empty (`futex_wake`, `__futex_wait`): `EINVAL`;
//! * `futex_wake` wakes nobody on a word nobody waits on (0), even at NULL
//!   (the address is never read on a wake);
//! * `futex_wait` with a stale value is `EAGAIN`; with the value current, an
//!   absolute deadline already past is `ETIMEDOUT` on `CLOCK_MONOTONIC` and
//!   `CLOCK_REALTIME`, and any other clock is `EINVAL`;
//! * `futex_requeue` takes two waiter entries, compares the first's value
//!   (`EAGAIN` when stale), refuses a flag and a negative count (`EINVAL`),
//!   and requeues nobody off an empty word (0);
//! * `futex_waitv` refuses an empty or oversized vector (more than 128), a
//!   flag and a reserved field (`EINVAL`), answers `EAGAIN` when any word is
//!   stale and `ETIMEDOUT` past its deadline, shared or private;
//! * a second thread waiting on two words through `futex_waitv` is woken by
//!   one `futex_wake` of the second word, and learns that word's index;
//! * a second thread in `futex_wait` is moved to another word by
//!   `futex_requeue` (one requeued, none woken), keeps its bitset there (a
//!   wake with a bitset that misses it wakes nobody) and is woken by one
//!   that matches, its `futex_wait` answering 0.
//!
//! Each waiter waits with a deadline ten seconds out, so a wait a wrong
//! model never ends still ends the run; each retry loop ends once its
//! waiter has left its call.
//!
//! glibc 2.39 wraps none of the rows, so the scenario runs through the
//! kernel vehicles. Every word is the scenario's own.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

/// `FUTEX2_SIZE_*` and `FUTEX2_PRIVATE` (include/uapi/linux/futex.h).
const SIZE_U8: i64 = 0x00;
const SIZE_U32: i64 = 0x02;
const SIZE_U64: i64 = 0x03;
const PRIVATE: i64 = 128;
const U32_PRIVATE: i64 = SIZE_U32 | PRIVATE;
/// A flag bit futex2 does not define.
const UNKNOWN_FLAG: i64 = 0x1000;
/// `FUTEX_BITSET_MATCH_ANY`: every bit a 32-bit word's bitset has.
const MATCH_ANY: i64 = 0xffff_ffff;
/// `FUTEX_WAITV_MAX`.
const WAITV_MAX: i64 = 128;

/// `struct futex_waitv`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Waiter {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

impl Waiter {
    fn on(word: &AtomicU32, val: u64, flags: i64) -> Waiter {
        Waiter {
            val,
            uaddr: word.as_ptr() as u64,
            flags: flags as u32,
            reserved: 0,
        }
    }
}

/// An absolute deadline at the clock's epoch: already past on every clock.
const PAST: timespec = timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

fn wake(p: &Probe, word: *const u32, mask: i64, nr: i64, flags: i64, what: &str) -> i64 {
    p.observed(
        Syscall::N_futex_wake,
        [word as i64, mask, nr, flags, 0, 0],
        &[
            ("word", what.into()),
            ("mask", mask.into()),
            ("nr", nr.into()),
            ("flags", flags.into()),
        ],
    )
}

fn wait(p: &Probe, word: &AtomicU32, val: i64, mask: i64, deadline: Option<i32>) -> i64 {
    let (timeout, clock) = match deadline {
        Some(clock) => (&PAST as *const timespec as i64, clock),
        None => (0, 0),
    };
    p.observed(
        Syscall::N_futex_wait,
        [
            word.as_ptr() as i64,
            val,
            mask,
            U32_PRIVATE,
            timeout,
            clock as i64,
        ],
        &[
            ("val", val.into()),
            ("mask", mask.into()),
            (
                "past_deadline_clock",
                deadline.map_or(Value::Null, Value::from),
            ),
        ],
    )
}

fn requeue(p: &Probe, waiters: &[Waiter; 2], flags: i64, nr_wake: i64, nr_requeue: i64) -> i64 {
    p.observed(
        Syscall::N_futex_requeue,
        [waiters.as_ptr() as i64, flags, nr_wake, nr_requeue, 0, 0],
        &[
            ("val", waiters[0].val.into()),
            ("second_flags", waiters[1].flags.into()),
            ("flags", flags.into()),
            ("nr_wake", nr_wake.into()),
            ("nr_requeue", nr_requeue.into()),
        ],
    )
}

fn waitv(p: &Probe, waiters: &[Waiter], nr: i64, flags: i64, deadline: Option<i32>) -> i64 {
    let (timeout, clock) = match deadline {
        Some(clock) => (&PAST as *const timespec as i64, clock),
        None => (0, 0),
    };
    p.observed(
        Syscall::N_futex_waitv,
        [waiters.as_ptr() as i64, nr, flags, timeout, clock as i64, 0],
        &[
            (
                "vals",
                waiters
                    .iter()
                    .map(|waiter| waiter.val)
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "waiter_flags",
                waiters
                    .iter()
                    .map(|waiter| waiter.flags)
                    .collect::<Vec<_>>()
                    .into(),
            ),
            ("nr", nr.into()),
            ("flags", flags.into()),
            (
                "past_deadline_clock",
                deadline.map_or(Value::Null, Value::from),
            ),
        ],
    )
}

pub fn run(p: &Probe) {
    let word = AtomicU32::new(5);
    let other = AtomicU32::new(0);
    let at = word.as_ptr() as *const u32;

    p.check(
        "futex_wake on a word nobody waits on wakes 0",
        wake(p, at, MATCH_ANY, 1, U32_PRIVATE, "word") == 0,
    );
    p.check(
        "futex_wake of no waiters at NULL wakes 0: a wake reads no word",
        wake(p, std::ptr::null(), MATCH_ANY, 1, U32_PRIVATE, "null") == 0,
    );
    for (mask, flags, label) in [
        (0, U32_PRIVATE, "an empty bitset is EINVAL"),
        (
            MATCH_ANY + 1,
            U32_PRIVATE,
            "a bitset wider than the 32-bit word is EINVAL",
        ),
        (MATCH_ANY, SIZE_U8 | PRIVATE, "an 8-bit word is EINVAL"),
        (MATCH_ANY, SIZE_U64 | PRIVATE, "a 64-bit word is EINVAL"),
        (
            MATCH_ANY,
            U32_PRIVATE | UNKNOWN_FLAG,
            "an unknown flag is EINVAL",
        ),
    ] {
        p.check(label, wake(p, at, mask, 1, flags, "word") == neg(EINVAL));
    }
    p.check(
        "a misaligned 32-bit word is EINVAL",
        wake(
            p,
            (at as *const u8).wrapping_add(1).cast(),
            MATCH_ANY,
            1,
            U32_PRIVATE,
            "misaligned",
        ) == neg(EINVAL),
    );

    p.check(
        "futex_wait with a stale value is EAGAIN",
        wait(p, &word, 4, MATCH_ANY, None) == neg(EAGAIN),
    );
    p.check(
        "a value wider than the 32-bit word is EINVAL",
        wait(p, &word, 1 << 32, MATCH_ANY, None) == neg(EINVAL),
    );
    p.check(
        "futex_wait with an empty bitset is EINVAL",
        wait(p, &word, 5, 0, Some(CLOCK_MONOTONIC)) == neg(EINVAL),
    );
    for (clock, label) in [
        (
            CLOCK_MONOTONIC,
            "a CLOCK_MONOTONIC deadline already past is ETIMEDOUT",
        ),
        (
            CLOCK_REALTIME,
            "a CLOCK_REALTIME deadline already past is ETIMEDOUT",
        ),
    ] {
        p.check(
            label,
            wait(p, &word, 5, MATCH_ANY, Some(clock)) == neg(ETIMEDOUT),
        );
    }
    p.check(
        "a deadline on any other clock is EINVAL",
        wait(p, &word, 5, MATCH_ANY, Some(CLOCK_BOOTTIME)) == neg(EINVAL),
    );

    let pair = |val: u64, second: i64| {
        [
            Waiter::on(&word, val, U32_PRIVATE),
            Waiter::on(&other, 0, second),
        ]
    };
    p.check(
        "futex_requeue off a word nobody waits on moves 0",
        requeue(p, &pair(5, U32_PRIVATE), 0, 1, 1) == 0,
    );
    p.check(
        "futex_requeue with a stale first value is EAGAIN",
        requeue(p, &pair(4, U32_PRIVATE), 0, 1, 1) == neg(EAGAIN),
    );
    p.check(
        "futex_requeue with a flag is EINVAL",
        requeue(p, &pair(5, U32_PRIVATE), 1, 1, 1) == neg(EINVAL),
    );
    p.check(
        "futex_requeue to an 8-bit word is EINVAL",
        requeue(p, &pair(5, SIZE_U8), 0, 1, 1) == neg(EINVAL),
    );
    p.check(
        "futex_requeue of a negative count is EINVAL",
        requeue(p, &pair(5, U32_PRIVATE), 0, -1, 1) == neg(EINVAL),
    );

    let current = [Waiter::on(&word, 5, U32_PRIVATE)];
    let stale = [Waiter::on(&word, 4, U32_PRIVATE)];
    let shared = [Waiter::on(&word, 5, SIZE_U32)];
    let reserved = [Waiter {
        reserved: 1,
        ..current[0]
    }];
    let oversized = vec![current[0]; WAITV_MAX as usize + 1];
    p.check(
        "futex_waitv of no waiters is EINVAL",
        waitv(p, &current, 0, 0, None) == neg(EINVAL),
    );
    p.check(
        "futex_waitv of more than 128 waiters is EINVAL",
        waitv(p, &oversized, WAITV_MAX + 1, 0, None) == neg(EINVAL),
    );
    p.check(
        "futex_waitv with a flag is EINVAL",
        waitv(p, &current, 1, 1, None) == neg(EINVAL),
    );
    p.check(
        "futex_waitv with a reserved field set is EINVAL",
        waitv(p, &reserved, 1, 0, Some(CLOCK_MONOTONIC)) == neg(EINVAL),
    );
    p.check(
        "futex_waitv with a stale value is EAGAIN",
        waitv(p, &stale, 1, 0, None) == neg(EAGAIN),
    );
    p.check(
        "futex_waitv past its CLOCK_MONOTONIC deadline is ETIMEDOUT",
        waitv(p, &current, 1, 0, Some(CLOCK_MONOTONIC)) == neg(ETIMEDOUT),
    );
    p.check(
        "a shared futex_waitv past its deadline is ETIMEDOUT too",
        waitv(p, &shared, 1, 0, Some(CLOCK_MONOTONIC)) == neg(ETIMEDOUT),
    );
    p.check(
        "futex_waitv on another clock is EINVAL",
        waitv(p, &current, 1, 0, Some(CLOCK_BOOTTIME)) == neg(EINVAL),
    );

    waitv_handshake(p, &word, &other);
    requeue_handshake(p);
}

/// An absolute `CLOCK_MONOTONIC` deadline ten seconds from now: far past
/// any wake natively, and a bound on a waiter a wrong model never wakes.
fn far_deadline() -> timespec {
    // SAFETY: an all-zero timespec is a valid out-parameter.
    let mut now: timespec = unsafe { std::mem::zeroed() };
    // SAFETY: reads the clock into `now` (unrecorded: its value is not a
    // property under test).
    unsafe { clock_gettime(CLOCK_MONOTONIC, &mut now) };
    timespec {
        tv_sec: now.tv_sec + 10,
        tv_nsec: now.tv_nsec,
    }
}

/// Not yet answered: the waiting thread is still in its call.
const PENDING: i64 = i64::MIN;

/// Retry `attempt` (unobserved) until it answers something other than 0 or
/// `done` says the waiting thread has left its call: how often it runs
/// before the waiter sleeps is the schedule's business. The last answer.
fn retry(p: &Probe, done: &AtomicI64, attempt: impl Fn() -> i64) -> i64 {
    p.rec.quiet(|| {
        loop {
            let r = attempt();
            if r != 0 || done.load(Ordering::SeqCst) != PENDING {
                break r;
            }
            p.nanosleep(0, 1_000_000);
        }
    })
}

/// A helper waits on two words through `futex_waitv`; the main thread wakes
/// the second until a wake finds it.
fn waitv_handshake(p: &Probe, word: &AtomicU32, other: &AtomicU32) {
    let woken = AtomicI64::new(PENDING);
    let words = [
        Waiter::on(word, 5, U32_PRIVATE),
        Waiter::on(other, 0, U32_PRIVATE),
    ];
    let deadline = far_deadline();
    let wakes = std::thread::scope(|scope| {
        scope.spawn(|| {
            let index = p.rec.quiet(|| {
                loop {
                    let r = p.call_unrecorded(
                        Syscall::N_futex_waitv,
                        [
                            words.as_ptr() as i64,
                            2,
                            0,
                            &deadline as *const timespec as i64,
                            CLOCK_MONOTONIC as i64,
                            0,
                        ],
                    );
                    // A signal could interrupt the wait; nothing else here
                    // returns early.
                    if r != neg(EINTR) {
                        break r;
                    }
                }
            });
            woken.store(index, Ordering::SeqCst);
        });
        retry(p, &woken, || {
            p.call_unrecorded(
                Syscall::N_futex_wake,
                [other.as_ptr() as i64, MATCH_ANY, 1, U32_PRIVATE, 0, 0],
            )
        })
    });
    let index = woken.load(Ordering::SeqCst);
    p.mark(
        "futex2_waitv_handshake",
        &[
            ("wake_result", wakes.into()),
            ("waitv_result", index.into()),
        ],
    );
    p.check(
        "one futex_wake of the second word wakes the futex_waitv waiter",
        wakes == 1,
    );
    p.check(
        "futex_waitv answers the index of the word that woke it",
        index == 1,
    );
}

/// The bitset a [`requeue_handshake`] waiter waits with, and one that
/// misses it.
const WAITER_BITS: i64 = 0x1;
const OTHER_BITS: i64 = 0x2;

/// A helper sleeps in `futex_wait` on one word with a bitset; the main
/// thread requeues it onto a second word (retrying until the requeue finds
/// it), then wakes the second word with a bitset that misses the waiter's
/// (nobody), and with the waiter's own (the waiter, whose `futex_wait`
/// answers 0).
fn requeue_handshake(p: &Probe) {
    let from = AtomicU32::new(0);
    let to = AtomicU32::new(0);
    let waited = AtomicI64::new(PENDING);
    let deadline = far_deadline();
    let (moved, missed, woke) = std::thread::scope(|scope| {
        scope.spawn(|| {
            let r = p.rec.quiet(|| {
                loop {
                    let r = p.call_unrecorded(
                        Syscall::N_futex_wait,
                        [
                            from.as_ptr() as i64,
                            0,
                            WAITER_BITS,
                            U32_PRIVATE,
                            &deadline as *const timespec as i64,
                            CLOCK_MONOTONIC as i64,
                        ],
                    );
                    if r != neg(EINTR) {
                        break r;
                    }
                }
            });
            waited.store(r, Ordering::SeqCst);
        });
        let pair = [
            Waiter::on(&from, 0, U32_PRIVATE),
            Waiter::on(&to, 0, U32_PRIVATE),
        ];
        let moved = retry(p, &waited, || {
            p.call_unrecorded(
                Syscall::N_futex_requeue,
                [pair.as_ptr() as i64, 0, 0, 1, 0, 0],
            )
        });
        let missed = wake(p, to.as_ptr(), OTHER_BITS, 1, U32_PRIVATE, "requeued-to");
        let woke = wake(p, to.as_ptr(), WAITER_BITS, 1, U32_PRIVATE, "requeued-to");
        (moved, missed, woke)
    });
    let waited = waited.load(Ordering::SeqCst);
    p.mark(
        "futex2_requeue_handshake",
        &[
            ("requeue_result", moved.into()),
            ("wait_result", waited.into()),
        ],
    );
    p.check(
        "futex_requeue moves the waiter to the second word, waking none",
        moved == 1,
    );
    p.check(
        "a wake whose bitset misses the requeued waiter's wakes nobody",
        missed == 0,
    );
    p.check(
        "a wake with the waiter's bitset wakes it on the second word",
        woke == 1,
    );
    p.check("the woken futex_wait answers 0", waited == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/futex2",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_futex_wake,
        Syscall::N_futex_wait,
        Syscall::N_futex_requeue,
        Syscall::N_futex_waitv,
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::KERNEL,
        what: "the futex2 rows are Trap(unmodeled) in the registry (the scheduler models only the multiplexed futex row), so the SUD dispatcher aborts at the first futex_wake",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall futex_wake (nr",
        },
    }],
    kernel_floor: Some(KernelFloor {
        release: "6.7",
        why: "futex_wake, futex_wait and futex_requeue first appear in Linux 6.7 (their registry rows carry no date)",
    }),
    ..DEFAULTS
};
