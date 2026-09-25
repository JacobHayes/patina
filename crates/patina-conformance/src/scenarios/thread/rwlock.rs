//! thread/rwlock — glibc's reader-writer locks (nptl
//! pthread_rwlock_common.c), by kind:
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
//!   acquires it once every read lock is released; and a releasing writer
//!   hands the lock to a waiting reader before a waiting writer;
//! * `PTHREAD_RWLOCK_PREFER_WRITER_NP` admits readers the same way, but a
//!   releasing writer hands the lock to the waiting writer first;
//! * `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`, from the attribute or
//!   glibc's static initializer, also hands over writer to writer, and a
//!   new reader's `tryrdlock` is `EBUSY` while a writer waits;
//! * the writer is the thread: the main thread unlocks a write lock it
//!   took before it queried its signal mask.
//!
//! pthread functions return the error number; each is recorded as `-error`.
//! A libc-only subject, so the libc vehicle alone.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use crate::signals as support;

/// glibc's `pthread.h` rwlock kinds (the `libc` crate has them only for
/// uclibc).
const PTHREAD_RWLOCK_PREFER_WRITER_NP: c_int = 1;
const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: c_int = 2;

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

/// A rwlock of a writer-preferring kind, in a box, and its address: from
/// `pthread_rwlockattr_setkind_np`, or never initialized, from glibc's
/// `PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP` (`__flags`, the
/// `unsigned int` at byte 48, set to the kind).
fn init_kind(p: &Probe, kind: c_int, from_attr: bool) -> (Box<pthread_rwlock_t>, usize) {
    // SAFETY: all-zero is PTHREAD_RWLOCK_INITIALIZER.
    let mut lock: Box<pthread_rwlock_t> = Box::new(unsafe { std::mem::zeroed() });
    let address = &*lock as *const pthread_rwlock_t as usize;
    if from_attr {
        // SAFETY: attribute storage of this frame, the box's lock.
        let error = unsafe {
            let mut attr: pthread_rwlockattr_t = std::mem::zeroed();
            pthread_rwlockattr_init(&mut attr);
            let set = pthread_rwlockattr_setkind_np(&mut attr, kind);
            let error = if set != 0 {
                set
            } else {
                pthread_rwlock_init(pointer(address), &attr)
            };
            pthread_rwlockattr_destroy(&mut attr);
            error
        };
        p.rec
            .event("pthread_rwlock_init", -(error as i64))
            .arg("kind", kind as i64)
            .emit();
        p.require("pthread_rwlock_init", error == 0);
    } else {
        // SAFETY: `__flags` lies within the lock's 56 bytes.
        unsafe {
            (&raw mut *lock)
                .cast::<u8>()
                .add(48)
                .cast::<c_uint>()
                .write(kind as c_uint)
        };
    }
    (lock, address)
}

/// While the main thread holds a read lock and a writer waits for it,
/// another thread's `tryrdlock` (0 when it barges past the writer).
fn reader_past_waiting_writer(p: &Probe, address: usize) -> i64 {
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
        let barged = worker_try(p, "pthread_rwlock_tryrdlock", address);
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
        barged
    })
}

/// The main thread write-locks, a reader and then a writer park on the
/// lock, and the main thread unlocks: which of the two acquires it first.
fn first_after_writer(p: &Probe, address: usize) -> &'static str {
    p.check("wrlock", call(p, "pthread_rwlock_wrlock", address) == 0);
    let next = AtomicUsize::new(0);
    let reader_at = AtomicUsize::new(usize::MAX);
    let writer_at = AtomicUsize::new(usize::MAX);
    let tids = [AtomicI32::new(0), AtomicI32::new(0)];
    std::thread::scope(|scope| {
        for (write, tid) in [false, true].into_iter().zip(&tids) {
            let (next, at) = (&next, if write { &writer_at } else { &reader_at });
            scope.spawn(move || {
                tid.store(support::gettid(), Ordering::SeqCst);
                let lock = pointer(address);
                // SAFETY: an initialized rwlock that outlives the scope.
                let error = unsafe {
                    if write {
                        pthread_rwlock_wrlock(lock)
                    } else {
                        pthread_rwlock_rdlock(lock)
                    }
                };
                if error == 0 {
                    at.store(next.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
                    // SAFETY: the worker holds it.
                    unsafe { pthread_rwlock_unlock(lock) };
                }
            });
            p.rec.quiet(|| {
                support::wait_until(Duration::from_millis(1), || tid.load(Ordering::SeqCst) != 0);
                support::until_parked(tid.load(Ordering::SeqCst));
            });
        }
        p.check(
            "unlock the write lock",
            call(p, "pthread_rwlock_unlock", address) == 0,
        );
    });
    let first = match (reader_at.into_inner(), writer_at.into_inner()) {
        (reader, writer) if reader < writer => "reader",
        (reader, writer) if writer < reader => "writer",
        _ => "neither",
    };
    p.rec
        .event("first_after_writer", 0)
        .field("first", first)
        .emit();
    first
}

/// The writer-preferring kinds: writer-to-writer hand-over, and whether a
/// new reader barges past a waiting writer.
fn writer_kinds(p: &Probe) {
    let (_lock, address) = init_kind(p, PTHREAD_RWLOCK_PREFER_WRITER_NP, true);
    p.check(
        "PREFER_WRITER_NP: another reader acquires the lock past the waiting writer",
        reader_past_waiting_writer(p, address) == 0,
    );
    p.check(
        "PREFER_WRITER_NP: a releasing writer hands over to the waiting writer",
        first_after_writer(p, address) == "writer",
    );
    p.check("destroy", call(p, "pthread_rwlock_destroy", address) == 0);

    for from_attr in [true, false] {
        let (_lock, address) =
            init_kind(p, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, from_attr);
        p.check(
            "PREFER_WRITER_NONRECURSIVE_NP: another reader's tryrdlock is EBUSY while a writer waits",
            reader_past_waiting_writer(p, address) == neg(EBUSY),
        );
        p.check(
            "PREFER_WRITER_NONRECURSIVE_NP: a releasing writer hands over to the waiting writer",
            first_after_writer(p, address) == "writer",
        );
        p.check("destroy", call(p, "pthread_rwlock_destroy", address) == 0);
    }
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
    p.check(
        "a releasing writer hands the lock to the waiting reader first",
        first_after_writer(p, address) == "reader",
    );
    p.check("destroy", call(p, "pthread_rwlock_destroy", address) == 0);

    writer_kinds(p);
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
    ..DEFAULTS
};
