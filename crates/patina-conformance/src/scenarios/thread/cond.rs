//! thread/cond — glibc's condition variables (nptl pthread_cond_wait.c)
//! with default attributes (`CLOCK_REALTIME` deadlines):
//!
//! * `pthread_cond_signal` wakes a waiter and `pthread_cond_broadcast`
//!   wakes every waiter, each returning 0 with the mutex held again;
//! * `pthread_cond_timedwait` returns 0 when signalled before its deadline,
//!   and `ETIMEDOUT` once the `CLOCK_REALTIME` deadline passes, no earlier
//!   than it and not far past it (a wait judged on another clock would end
//!   decades later), with the mutex held again; a deadline already past
//!   times out at once, and so does a negative one (glibc's futex wait answers `ETIMEDOUT` for a
//!   negative `tv_sec`); a `tv_nsec` outside `[0, 1e9)` is `EINVAL`, the
//!   mutex never released.
//!
//! The mutex is error-checking, so its `unlock` succeeding shows the
//! caller holds it. Workers wait under the usual predicate loop and the
//! main thread signals only once each is waiting (it has set its flag and
//! released the mutex inside the wait), so no wakeup is lost natively and
//! a spurious one changes nothing recorded. The workers start before the
//! main thread first locks (a mutex locked before any thread exists is
//! `thread/mutex`'s subject). pthread functions return the error number;
//! each is recorded as `-error`. A libc-only subject, so the libc vehicle
//! alone.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crate::signals as support;

/// A condition variable, its error-checking mutex, and the predicate the
/// waiters loop on, at stable addresses.
struct Shared {
    cond: UnsafeCell<pthread_cond_t>,
    mutex: UnsafeCell<pthread_mutex_t>,
    ready: AtomicBool,
    waiting: AtomicUsize,
}

// SAFETY: the pthread objects are only reached through the pthread calls,
// which synchronize their own state.
unsafe impl Sync for Shared {}

fn record(p: &Probe, op: &str, case: &str, error: c_int) -> i64 {
    let result = -(error as i64);
    p.rec.event(op, result).arg("case", case).emit();
    result
}

impl Shared {
    fn cond(&self) -> *mut pthread_cond_t {
        self.cond.get()
    }

    fn mutex(&self) -> *mut pthread_mutex_t {
        self.mutex.get()
    }

    fn lock(&self) {
        // SAFETY: an initialized mutex.
        let error = unsafe { pthread_mutex_lock(self.mutex()) };
        assert_eq!(error, 0, "pthread_mutex_lock");
    }

    /// Unlock, recorded: success shows the caller held the mutex.
    fn unlock_held(&self, p: &Probe, case: &str) {
        // SAFETY: an initialized mutex.
        let error = unsafe { pthread_mutex_unlock(self.mutex()) };
        p.check(
            "the mutex is held again",
            record(p, "pthread_mutex_unlock", case, error) == 0,
        );
    }

    /// On a worker: wait until `ready` (a predicate loop, so a spurious
    /// wakeup waits again); the last wait's error number and the error
    /// number of the unlock that follows it.
    fn wait_ready(&self) -> (c_int, c_int) {
        self.lock();
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let mut error = 0;
        while !self.ready.load(Ordering::SeqCst) && error == 0 {
            // SAFETY: initialized objects; the worker holds the mutex.
            error = unsafe { pthread_cond_wait(self.cond(), self.mutex()) };
        }
        // SAFETY: an initialized mutex the wait should have re-acquired.
        (error, unsafe { pthread_mutex_unlock(self.mutex()) })
    }

    /// On a worker: a timed wait for `ready` with a deadline `ns` from now.
    fn timedwait_ready(&self, ns: i64) -> (c_int, c_int) {
        self.lock();
        let deadline = realtime_ns() + ns;
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let mut error = 0;
        while !self.ready.load(Ordering::SeqCst) && error == 0 {
            error = self.timedwait(timespec {
                tv_sec: deadline / 1_000_000_000,
                tv_nsec: deadline % 1_000_000_000,
            });
        }
        // SAFETY: an initialized mutex the wait should have re-acquired.
        (error, unsafe { pthread_mutex_unlock(self.mutex()) })
    }

    fn timedwait(&self, deadline: timespec) -> c_int {
        // SAFETY: initialized objects; the caller holds the mutex.
        unsafe { pthread_cond_timedwait(self.cond(), self.mutex(), &deadline) }
    }

    /// Wait (unobserved) until `n` workers are waiting, then, holding the
    /// mutex, make the predicate true and wake them with `wake`.
    fn release(&self, p: &Probe, n: usize, op: &str, case: &str) -> i64 {
        p.rec.quiet(|| {
            support::wait_until(Duration::from_millis(1), || {
                self.waiting.load(Ordering::SeqCst) >= n
            })
        });
        p.require(
            "the workers are waiting",
            self.waiting.load(Ordering::SeqCst) >= n,
        );
        self.lock();
        self.ready.store(true, Ordering::SeqCst);
        // SAFETY: an initialized condition variable.
        let error = unsafe {
            if op == "pthread_cond_broadcast" {
                pthread_cond_broadcast(self.cond())
            } else {
                pthread_cond_signal(self.cond())
            }
        };
        let result = record(p, op, case, error);
        // SAFETY: the main thread holds the mutex.
        unsafe { pthread_mutex_unlock(self.mutex()) };
        result
    }

    fn reset(&self) {
        self.ready.store(false, Ordering::SeqCst);
        self.waiting.store(0, Ordering::SeqCst);
    }
}

fn monotonic_ns() -> i64 {
    let mut now = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a writable timespec.
    unsafe { clock_gettime(CLOCK_MONOTONIC, &mut now) };
    now.tv_sec * 1_000_000_000 + now.tv_nsec
}

fn realtime_ns() -> i64 {
    let mut now = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a writable timespec.
    unsafe { clock_gettime(CLOCK_REALTIME, &mut now) };
    now.tv_sec * 1_000_000_000 + now.tv_nsec
}

/// Record a worker's wait result and its unlock after it, which succeeds
/// only if the wait returned with the mutex held.
fn waited(p: &Probe, op: &str, case: &str, (wait, unlock): (c_int, c_int)) -> i64 {
    let result = record(p, op, case, wait);
    p.check(
        "the mutex is held again",
        record(p, "pthread_mutex_unlock", case, unlock) == 0,
    );
    result
}

pub fn run(p: &Probe) {
    // SAFETY: all-zero objects, initialized below before any use.
    let shared: Box<Shared> = Box::new(unsafe { std::mem::zeroed() });
    // SAFETY: the box's storage.
    let error = unsafe {
        let mut attr: pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, PTHREAD_MUTEX_ERRORCHECK);
        let error = pthread_mutex_init(shared.mutex(), &attr);
        pthread_mutexattr_destroy(&mut attr);
        error
    };
    p.require("pthread_mutex_init", error == 0);
    p.check(
        "pthread_cond_init",
        // SAFETY: the box's storage, default attributes.
        record(p, "pthread_cond_init", "default", unsafe {
            pthread_cond_init(shared.cond(), std::ptr::null())
        }) == 0,
    );
    let shared = &*shared;

    // signal wakes the waiter.
    let error = std::thread::scope(|scope| {
        let worker = scope.spawn(|| shared.wait_ready());
        p.check(
            "pthread_cond_signal",
            shared.release(p, 1, "pthread_cond_signal", "one waiter") == 0,
        );
        worker.join().expect("the worker")
    });
    p.check(
        "the signalled waiter returns 0",
        waited(p, "pthread_cond_wait", "signalled", error) == 0,
    );

    // broadcast wakes every waiter.
    shared.reset();
    let errors = std::thread::scope(|scope| {
        let first = scope.spawn(|| shared.wait_ready());
        let second = scope.spawn(|| shared.wait_ready());
        p.check(
            "pthread_cond_broadcast",
            shared.release(p, 2, "pthread_cond_broadcast", "two waiters") == 0,
        );
        [
            first.join().expect("a worker"),
            second.join().expect("a worker"),
        ]
    });
    for error in errors {
        p.check(
            "each broadcast waiter returns 0",
            waited(p, "pthread_cond_wait", "broadcast", error) == 0,
        );
    }

    // A timed wait signalled before its deadline.
    shared.reset();
    let error = std::thread::scope(|scope| {
        let worker = scope.spawn(|| shared.timedwait_ready(support::PROGRESS_DEADLINE_NS));
        shared.release(p, 1, "pthread_cond_signal", "timed waiter");
        worker.join().expect("the worker")
    });
    p.check(
        "a timed wait signalled before its deadline returns 0",
        waited(p, "pthread_cond_timedwait", "signalled", error) == 0,
    );

    // A timed wait nobody signals.
    shared.reset();
    shared.lock();
    let started = monotonic_ns();
    let deadline = realtime_ns() + 50_000_000;
    let error = shared.timedwait(timespec {
        tv_sec: deadline / 1_000_000_000,
        tv_nsec: deadline % 1_000_000_000,
    });
    let after = realtime_ns();
    let elapsed = monotonic_ns() - started;
    p.check(
        "an unsignalled timed wait is ETIMEDOUT",
        record(p, "pthread_cond_timedwait", "50ms", error) == neg(ETIMEDOUT),
    );
    p.check("no earlier than its deadline", after >= deadline);
    p.check(
        "and judged on CLOCK_REALTIME: it ends about 50 ms later",
        elapsed < 50_000_000 + support::PROGRESS_DEADLINE_NS,
    );
    shared.unlock_held(p, "50ms");

    shared.lock();
    let error = shared.timedwait(timespec {
        tv_sec: 1,
        tv_nsec: 0,
    });
    p.check(
        "a deadline already past is ETIMEDOUT",
        record(p, "pthread_cond_timedwait", "past", error) == neg(ETIMEDOUT),
    );
    shared.unlock_held(p, "past");

    shared.lock();
    let error = shared.timedwait(timespec {
        tv_sec: -1,
        tv_nsec: 0,
    });
    p.check(
        "a negative deadline is ETIMEDOUT",
        record(p, "pthread_cond_timedwait", "negative", error) == neg(ETIMEDOUT),
    );
    shared.unlock_held(p, "negative");

    shared.lock();
    let error = shared.timedwait(timespec {
        tv_sec: 1,
        tv_nsec: 1_000_000_000,
    });
    p.check(
        "tv_nsec past a second is EINVAL",
        record(p, "pthread_cond_timedwait", "invalid", error) == neg(EINVAL),
    );
    shared.unlock_held(p, "invalid");

    p.check(
        "pthread_cond_destroy",
        // SAFETY: an initialized condition variable nobody waits on.
        record(p, "pthread_cond_destroy", "idle", unsafe {
            pthread_cond_destroy(shared.cond())
        }) == 0,
    );
    // SAFETY: an initialized, unlocked mutex.
    unsafe { pthread_mutex_destroy(shared.mutex()) };
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/cond",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_futex, Syscall::N_clock_gettime],
    symbols: &[
        "pthread_cond_init",
        "pthread_cond_wait",
        "pthread_cond_timedwait",
        "pthread_cond_signal",
        "pthread_cond_broadcast",
        "pthread_cond_destroy",
        "pthread_mutex_init",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "pthread_mutex_destroy",
        "clock_gettime",
    ],
    ..DEFAULTS
};
