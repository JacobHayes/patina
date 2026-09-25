//! thread/rwlock — glibc's reader-writer locks (nptl
//! pthread_rwlock_common.c) with default attributes:
//!
//! * readers share: a reader rereads, `tryrdlock` and another thread's
//!   `tryrdlock` succeed, and a `trywrlock` by anyone is `EBUSY`; the lock is
//!   free after as many unlocks as read locks;
//! * a writer excludes: its own `wrlock` and `rdlock` are `EDEADLK` (the
//!   blocking calls check the current writer), its `tryrdlock` and
//!   `trywrlock` are `EBUSY` (the non-blocking ones do not), and another
//!   thread's try-locks are `EBUSY`;
//! * the default kind prefers readers (`PTHREAD_RWLOCK_PREFER_READER_NP`):
//!   while a reader holds the lock, a writer parks, and another thread's
//!   `tryrdlock` still acquires the lock past the waiting writer; the writer
//!   acquires it once every read lock is released;
//! * the writer is the thread: the main thread unlocks a write lock it
//!   took before it queried its signal mask.
//!
//! pthread functions return the error number; each is recorded as `-error`.
//! A libc-only subject, so the libc vehicle alone.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use crate::signals as support;

fn pointer(address: usize) -> *mut pthread_rwlock_t {
    address as *mut pthread_rwlock_t
}

fn record(p: &Probe, op: &str, by: &str, error: c_int) -> i64 {
    let result = -(error as i64);
    p.rec.event(op, result).arg("by", by).emit();
    result
}

/// The main thread's call `op` on the lock at `address`.
fn call(p: &Probe, op: &str, address: usize) -> i64 {
    let lock = pointer(address);
    // SAFETY: an initialized rwlock.
    let error = unsafe {
        match op {
            "pthread_rwlock_rdlock" => pthread_rwlock_rdlock(lock),
            "pthread_rwlock_tryrdlock" => pthread_rwlock_tryrdlock(lock),
            "pthread_rwlock_wrlock" => pthread_rwlock_wrlock(lock),
            "pthread_rwlock_trywrlock" => pthread_rwlock_trywrlock(lock),
            "pthread_rwlock_unlock" => pthread_rwlock_unlock(lock),
            "pthread_rwlock_destroy" => pthread_rwlock_destroy(lock),
            _ => unreachable!("{op}"),
        }
    };
    record(p, op, "owner", error)
}

/// Another thread's try-lock `op`, releasing what it acquires (unrecorded).
fn worker_try(p: &Probe, op: &str, address: usize) -> i64 {
    let write = op == "pthread_rwlock_trywrlock";
    let error = std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let lock = pointer(address);
                // SAFETY: an initialized rwlock that outlives the worker.
                unsafe {
                    let error = if write {
                        pthread_rwlock_trywrlock(lock)
                    } else {
                        pthread_rwlock_tryrdlock(lock)
                    };
                    if error == 0 {
                        pthread_rwlock_unlock(lock);
                    }
                    error
                }
            })
            .join()
            .expect("the worker")
    });
    record(p, op, "worker", error)
}

/// A default rwlock in a box (its address stays put) and that address.
fn init(p: &Probe) -> (Box<pthread_rwlock_t>, usize) {
    // SAFETY: all-zero is a valid (unused) rwlock to initialize.
    let lock: Box<pthread_rwlock_t> = Box::new(unsafe { std::mem::zeroed() });
    let address = &*lock as *const pthread_rwlock_t as usize;
    // SAFETY: the box's storage, default attributes.
    let error = unsafe { pthread_rwlock_init(pointer(address), std::ptr::null()) };
    record(p, "pthread_rwlock_init", "owner", error);
    p.require("pthread_rwlock_init", error == 0);
    (lock, address)
}

pub fn run(p: &Probe) {
    // Write-locked first thing, before the process has created a thread or
    // touched its signal state; the writer is the thread across both.
    let (_first, address) = init(p);
    p.check("wrlock", call(p, "pthread_rwlock_wrlock", address) == 0);
    let mut old = support::empty_set();
    // SAFETY: a query into a writable set.
    let queried = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut old) };
    p.rec
        .event("sigprocmask", crate::vehicle::fold_errno(queried as i64))
        .emit();
    p.check(
        "the writer unlocks, whatever the thread did since it locked",
        call(p, "pthread_rwlock_unlock", address) == 0,
    );
    p.check("destroy", call(p, "pthread_rwlock_destroy", address) == 0);

    let (_lock, address) = init(p);

    p.check("rdlock", call(p, "pthread_rwlock_rdlock", address) == 0);
    p.check(
        "a reader rereads",
        call(p, "pthread_rwlock_rdlock", address) == 0,
    );
    p.check(
        "tryrdlock by a reader",
        call(p, "pthread_rwlock_tryrdlock", address) == 0,
    );
    p.check(
        "trywrlock by a reader is EBUSY",
        call(p, "pthread_rwlock_trywrlock", address) == neg(EBUSY),
    );
    p.check(
        "another thread's tryrdlock shares the lock",
        worker_try(p, "pthread_rwlock_tryrdlock", address) == 0,
    );
    p.check(
        "another thread's trywrlock is EBUSY",
        worker_try(p, "pthread_rwlock_trywrlock", address) == neg(EBUSY),
    );
    for _ in 0..3 {
        p.check(
            "unlock a read lock",
            call(p, "pthread_rwlock_unlock", address) == 0,
        );
    }

    p.check(
        "free after as many unlocks as read locks: wrlock",
        call(p, "pthread_rwlock_wrlock", address) == 0,
    );
    p.check(
        "wrlock by the writer is EDEADLK",
        call(p, "pthread_rwlock_wrlock", address) == neg(EDEADLK),
    );
    p.check(
        "rdlock by the writer is EDEADLK",
        call(p, "pthread_rwlock_rdlock", address) == neg(EDEADLK),
    );
    p.check(
        "tryrdlock by the writer is EBUSY",
        call(p, "pthread_rwlock_tryrdlock", address) == neg(EBUSY),
    );
    p.check(
        "trywrlock by the writer is EBUSY",
        call(p, "pthread_rwlock_trywrlock", address) == neg(EBUSY),
    );
    p.check(
        "another thread's tryrdlock is EBUSY",
        worker_try(p, "pthread_rwlock_tryrdlock", address) == neg(EBUSY),
    );
    p.check(
        "another thread's trywrlock is EBUSY",
        worker_try(p, "pthread_rwlock_trywrlock", address) == neg(EBUSY),
    );
    p.check(
        "unlock the write lock",
        call(p, "pthread_rwlock_unlock", address) == 0,
    );

    // Reader preference: a writer parks behind a reader, and a new reader
    // acquires the lock past it.
    p.check("rdlock", call(p, "pthread_rwlock_rdlock", address) == 0);
    let tid = AtomicI32::new(0);
    let acquired = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            tid.store(support::gettid(), Ordering::SeqCst);
            // SAFETY: an initialized rwlock that outlives the scope.
            if unsafe { pthread_rwlock_wrlock(pointer(address)) } == 0 {
                acquired.store(true, Ordering::SeqCst);
                // SAFETY: the worker holds it.
                unsafe { pthread_rwlock_unlock(pointer(address)) };
            }
        });
        p.rec.quiet(|| {
            support::wait_until(Duration::from_millis(1), || tid.load(Ordering::SeqCst) != 0);
            support::until_parked(tid.load(Ordering::SeqCst));
        });
        p.check(
            "a writer parks while a reader holds the lock",
            !acquired.load(Ordering::SeqCst),
        );
        p.check(
            "another reader acquires the lock past the waiting writer",
            worker_try(p, "pthread_rwlock_tryrdlock", address) == 0,
        );
        p.check(
            "unlock the read lock",
            call(p, "pthread_rwlock_unlock", address) == 0,
        );
        p.rec.quiet(|| {
            support::wait_until(Duration::from_millis(1), || acquired.load(Ordering::SeqCst))
        });
        p.check(
            "the writer acquires the lock once every read lock is released",
            acquired.load(Ordering::SeqCst),
        );
    });
    p.check("destroy", call(p, "pthread_rwlock_destroy", address) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/rwlock",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_futex, Syscall::N_rt_sigprocmask],
    symbols: &[
        "pthread_rwlock_init",
        "pthread_rwlock_destroy",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_tryrdlock",
        "pthread_rwlock_wrlock",
        "pthread_rwlock_trywrlock",
        "pthread_rwlock_unlock",
        "sigprocmask",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: &[Vehicle::Libc],
            what: "the main thread's lock-owner identity changes when the thread runtime activates (patina-native-shim src/lib.rs current_task: UNMANAGED_TASK until ensure_active; a signal-state call such as sigprocmask activates it), so a write lock taken before that is owned by a task the main thread no longer is: its unlock is EPERM (rwlock_unlock) and the lock stays held (destroy EBUSY)",
            failure: Failure::Differs(&[
                Difference::field(4, "pthread_rwlock_unlock", "ret", Observed::Int(-1)),
                Difference::field(4, "pthread_rwlock_unlock", "errno", Observed::Str("EPERM")),
                Difference::check(
                    5,
                    "the writer unlocks, whatever the thread did since it locked",
                ),
                Difference::field(6, "pthread_rwlock_destroy", "ret", Observed::Int(-1)),
                Difference::field(6, "pthread_rwlock_destroy", "errno", Observed::Str("EBUSY")),
                Difference::check(7, "destroy"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: &[Vehicle::Libc],
            what: "the shim's rwlock table answers the writer's own tryrdlock and trywrlock EDEADLK (patina-native-shim src/lib.rs rwlock_tryrdlock/rwlock_trywrlock), where glibc's non-blocking calls do not check the writer and are EBUSY",
            failure: Failure::Differs(&[
                Difference::field(
                    33,
                    "pthread_rwlock_tryrdlock",
                    "errno",
                    Observed::Str("EDEADLK"),
                ),
                Difference::check(34, "tryrdlock by the writer is EBUSY"),
                Difference::field(
                    35,
                    "pthread_rwlock_trywrlock",
                    "errno",
                    Observed::Str("EDEADLK"),
                ),
                Difference::check(36, "trywrlock by the writer is EBUSY"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: &[Vehicle::Libc],
            what: "the shim's rwlock is writer-preferring whatever the attributes (patina_rwlock_init drops `attr`; rwlock_tryrdlock refuses while a writer waits), where glibc's default kind prefers readers: another thread's tryrdlock past the waiting writer is EBUSY",
            failure: Failure::Differs(&[
                Difference::field(46, "pthread_rwlock_tryrdlock", "ret", Observed::Int(-1)),
                Difference::field(
                    46,
                    "pthread_rwlock_tryrdlock",
                    "errno",
                    Observed::Str("EBUSY"),
                ),
                Difference::check(
                    47,
                    "another reader acquires the lock past the waiting writer",
                ),
            ]),
        },
    ],
    ..DEFAULTS
};
