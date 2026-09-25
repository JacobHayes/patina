//! thread/mutex — glibc's pthread mutexes by type (nptl
//! pthread_mutex_lock.c, pthread_mutex_trylock.c, pthread_mutex_unlock.c):
//!
//! * the default type: `trylock` of a held mutex is `EBUSY`, from its owner
//!   as from any other thread; `destroy` of a held mutex is `EBUSY`; the
//!   owner is the thread, so the main thread unlocks a mutex it locked
//!   before it queried its signal mask or created its first thread; a
//!   contended `lock` parks until the owner unlocks;
//! * `PTHREAD_MUTEX_ERRORCHECK`: relocking is `EDEADLK`, `trylock` by the
//!   owner is still `EBUSY`, and unlocking a mutex the caller does not hold
//!   (another thread's, or an unlocked one) is `EPERM`;
//! * `PTHREAD_MUTEX_RECURSIVE`: the owner relocks, and the mutex is free
//!   only after as many unlocks as locks;
//! * the static initializers need no `pthread_mutex_init`:
//!   `PTHREAD_MUTEX_INITIALIZER` is a default mutex and glibc's
//!   `PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP` a recursive one.
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

/// A mutex of one type, at a stable address.
struct Mutex {
    /// Never freed: a later mutex must not reuse the address of one the
    /// implementation may still hold (a gap below leaves one held).
    raw: &'static mut pthread_mutex_t,
    kind: &'static str,
}

impl Mutex {
    fn address(&self) -> usize {
        &*self.raw as *const pthread_mutex_t as usize
    }
}

fn pointer(address: usize) -> *mut pthread_mutex_t {
    address as *mut pthread_mutex_t
}

fn record(p: &Probe, op: &str, mutex: &Mutex, by: &str, error: c_int) -> i64 {
    let result = -(error as i64);
    p.rec
        .event(op, result)
        .arg("type", mutex.kind)
        .arg("by", by)
        .emit();
    result
}

fn init(p: &Probe, kind: &'static str, type_: Option<c_int>) -> Mutex {
    // SAFETY: all-zero is a valid (unused) pthread_mutex_t to initialize.
    let mutex = Mutex {
        raw: Box::leak(Box::new(unsafe { std::mem::zeroed() })),
        kind,
    };
    // SAFETY: attribute and mutex storage are this frame's and the box's.
    let error = unsafe {
        match type_ {
            None => pthread_mutex_init(mutex.raw, std::ptr::null()),
            Some(type_) => {
                let mut attr: pthread_mutexattr_t = std::mem::zeroed();
                pthread_mutexattr_init(&mut attr);
                pthread_mutexattr_settype(&mut attr, type_);
                let error = pthread_mutex_init(mutex.raw, &attr);
                pthread_mutexattr_destroy(&mut attr);
                error
            }
        }
    };
    record(p, "pthread_mutex_init", &mutex, "owner", error);
    p.require("pthread_mutex_init", error == 0);
    mutex
}

fn lock(p: &Probe, mutex: &Mutex) -> i64 {
    // SAFETY: an initialized mutex.
    record(p, "pthread_mutex_lock", mutex, "owner", unsafe {
        pthread_mutex_lock(pointer(mutex.address()))
    })
}

fn trylock(p: &Probe, mutex: &Mutex) -> i64 {
    // SAFETY: an initialized mutex.
    record(p, "pthread_mutex_trylock", mutex, "owner", unsafe {
        pthread_mutex_trylock(pointer(mutex.address()))
    })
}

fn unlock(p: &Probe, mutex: &Mutex) -> i64 {
    // SAFETY: an initialized mutex.
    record(p, "pthread_mutex_unlock", mutex, "owner", unsafe {
        pthread_mutex_unlock(pointer(mutex.address()))
    })
}

fn destroy(p: &Probe, mutex: &Mutex) -> i64 {
    // SAFETY: an initialized mutex.
    record(p, "pthread_mutex_destroy", mutex, "owner", unsafe {
        pthread_mutex_destroy(pointer(mutex.address()))
    })
}

/// Run `body` on a new thread and answer what it returns.
fn on_worker(body: impl FnOnce() -> c_int + Send) -> c_int {
    std::thread::scope(|scope| scope.spawn(body).join().expect("the worker"))
}

/// Another thread's `trylock`, releasing what it acquires (unrecorded).
fn worker_trylock(p: &Probe, mutex: &Mutex) -> i64 {
    let address = mutex.address();
    let error = on_worker(move || {
        // SAFETY: an initialized mutex that outlives the worker.
        let error = unsafe { pthread_mutex_trylock(pointer(address)) };
        if error == 0 {
            // SAFETY: the worker holds it.
            unsafe { pthread_mutex_unlock(pointer(address)) };
        }
        error
    });
    record(p, "pthread_mutex_trylock", mutex, "worker", error)
}

/// Another thread's `unlock` of a mutex it does not hold.
fn worker_unlock(p: &Probe, mutex: &Mutex) -> i64 {
    let address = mutex.address();
    // SAFETY: an initialized mutex that outlives the worker.
    let error = on_worker(move || unsafe { pthread_mutex_unlock(pointer(address)) });
    record(p, "pthread_mutex_unlock", mutex, "worker", error)
}

/// A mutex from a static initializer, never passed to `pthread_mutex_init`:
/// `PTHREAD_MUTEX_INITIALIZER` (all zero), or glibc's
/// `PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP` (`__kind`, the fifth `int` of
/// `struct __pthread_mutex_s`, set to `PTHREAD_MUTEX_RECURSIVE`).
fn initializer(kind: &'static str, recursive: bool) -> Mutex {
    // SAFETY: all-zero is PTHREAD_MUTEX_INITIALIZER.
    let raw: &'static mut pthread_mutex_t = Box::leak(Box::new(unsafe { std::mem::zeroed() }));
    if recursive {
        // SAFETY: `__kind` lies within the mutex's 40 bytes.
        unsafe {
            (&raw mut *raw)
                .cast::<c_int>()
                .add(4)
                .write(PTHREAD_MUTEX_RECURSIVE)
        };
    }
    Mutex { raw, kind }
}

/// `sigprocmask(SIG_BLOCK, NULL, &old)`: a query that changes nothing.
fn query_mask(p: &Probe) -> i64 {
    let mut old = support::empty_set();
    // SAFETY: a writable set.
    let error = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut old) };
    let result = crate::vehicle::fold_errno(error as i64);
    p.rec.event("sigprocmask", result).emit();
    result
}

fn default_type(p: &Probe) {
    // Both locked first thing: before the process has created a thread or
    // touched its signal state.
    let mutex = init(p, "default", None);
    p.check("lock", lock(p, &mutex) == 0);
    let other = init(p, "default", None);
    p.check("lock", lock(p, &other) == 0);
    p.check("query the signal mask", query_mask(p) == 0);
    p.check(
        "the owner unlocks, whatever the thread did since it locked",
        unlock(p, &other) == 0,
    );
    p.check("destroy", destroy(p, &other) == 0);
    p.check(
        "trylock by another thread is EBUSY",
        worker_trylock(p, &mutex) == neg(EBUSY),
    );
    p.check(
        "destroy of a held mutex is EBUSY",
        destroy(p, &mutex) == neg(EBUSY),
    );
    p.check(
        "the owner unlocks, whatever threads it created since it locked",
        unlock(p, &mutex) == 0,
    );
    p.check("destroy", destroy(p, &mutex) == 0);

    // A contended lock parks until the owner unlocks.
    let mutex = init(p, "default", None);
    p.check("lock", lock(p, &mutex) == 0);
    p.check(
        "trylock by the owner is EBUSY",
        trylock(p, &mutex) == neg(EBUSY),
    );
    let tid = AtomicI32::new(0);
    let acquired = AtomicBool::new(false);
    let address = mutex.address();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            tid.store(support::gettid(), Ordering::SeqCst);
            // SAFETY: an initialized mutex that outlives the scope.
            if unsafe { pthread_mutex_lock(pointer(address)) } == 0 {
                acquired.store(true, Ordering::SeqCst);
                // SAFETY: the worker holds it.
                unsafe { pthread_mutex_unlock(pointer(address)) };
            }
        });
        p.rec.quiet(|| {
            support::wait_until(Duration::from_millis(1), || tid.load(Ordering::SeqCst) != 0);
            support::until_parked(tid.load(Ordering::SeqCst));
        });
        p.check(
            "a contended lock has not returned while the owner holds it",
            !acquired.load(Ordering::SeqCst),
        );
        p.check("unlock", unlock(p, &mutex) == 0);
        p.rec.quiet(|| {
            support::wait_until(Duration::from_millis(1), || acquired.load(Ordering::SeqCst))
        });
        p.check(
            "the unlock hands the mutex to the contender",
            acquired.load(Ordering::SeqCst),
        );
    });
    p.check("destroy", destroy(p, &mutex) == 0);
}

fn errorcheck_type(p: &Probe) {
    let mutex = init(p, "errorcheck", Some(PTHREAD_MUTEX_ERRORCHECK));
    p.check("lock", lock(p, &mutex) == 0);
    p.check(
        "relock by the owner is EDEADLK",
        lock(p, &mutex) == neg(EDEADLK),
    );
    p.check(
        "trylock by the owner is still EBUSY",
        trylock(p, &mutex) == neg(EBUSY),
    );
    p.check(
        "unlock by a thread that does not hold it is EPERM",
        worker_unlock(p, &mutex) == neg(EPERM),
    );
    p.check("unlock", unlock(p, &mutex) == 0);
    p.check(
        "unlock of an unlocked mutex is EPERM",
        unlock(p, &mutex) == neg(EPERM),
    );
    p.check("destroy", destroy(p, &mutex) == 0);
}

fn recursive_type(p: &Probe) {
    let mutex = init(p, "recursive", Some(PTHREAD_MUTEX_RECURSIVE));
    p.check("lock", lock(p, &mutex) == 0);
    p.check("the owner relocks", lock(p, &mutex) == 0);
    p.check("unlock once", unlock(p, &mutex) == 0);
    p.check(
        "still held after one of two unlocks",
        worker_trylock(p, &mutex) == neg(EBUSY),
    );
    p.check("unlock again", unlock(p, &mutex) == 0);
    p.check(
        "free after as many unlocks as locks",
        worker_trylock(p, &mutex) == 0,
    );
    p.check("destroy", destroy(p, &mutex) == 0);
}

fn initializers(p: &Probe) {
    let mutex = initializer("static default", false);
    p.check("lock", lock(p, &mutex) == 0);
    p.check(
        "trylock by another thread is EBUSY",
        worker_trylock(p, &mutex) == neg(EBUSY),
    );
    p.check("unlock", unlock(p, &mutex) == 0);

    let mutex = initializer("static recursive", true);
    p.check("lock", lock(p, &mutex) == 0);
    p.check("the owner relocks", lock(p, &mutex) == 0);
    p.check("unlock once", unlock(p, &mutex) == 0);
    p.check("unlock again", unlock(p, &mutex) == 0);
}

pub fn run(p: &Probe) {
    default_type(p);
    errorcheck_type(p);
    recursive_type(p);
    initializers(p);
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/mutex",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_futex, Syscall::N_rt_sigprocmask],
    symbols: &[
        "pthread_mutex_init",
        "pthread_mutex_lock",
        "pthread_mutex_trylock",
        "pthread_mutex_unlock",
        "pthread_mutex_destroy",
        "sigprocmask",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: &[Vehicle::Libc],
            what: "the shim's mutex table answers a trylock by the owner EDEADLK (patina-native-shim src/lib.rs ThreadTable::trylock), where glibc's trylock of a held mutex of any non-recursive type is EBUSY",
            failure: Failure::Differs(&[
                Difference::field(
                    23,
                    "pthread_mutex_trylock",
                    "errno",
                    Observed::Str("EDEADLK"),
                ),
                Difference::check(24, "trylock by the owner is EBUSY"),
                Difference::field(
                    36,
                    "pthread_mutex_trylock",
                    "errno",
                    Observed::Str("EDEADLK"),
                ),
                Difference::check(37, "trylock by the owner is still EBUSY"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: &[Vehicle::Libc],
            what: "the shim's mutexes have no type: patina_mutex_init drops the attributes and a static initializer's kind (glibc's PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP) is never read, so every mutex is error-checking and a recursive one's relock is EDEADLK, one unlock frees it (another thread's trylock succeeds) and the second is EPERM",
            failure: Failure::Differs(&[
                Difference::field(49, "pthread_mutex_lock", "ret", Observed::Int(-1)),
                Difference::field(49, "pthread_mutex_lock", "errno", Observed::Str("EDEADLK")),
                Difference::check(50, "the owner relocks"),
                Difference::field(53, "pthread_mutex_trylock", "ret", Observed::Int(0)),
                Difference::field(53, "pthread_mutex_trylock", "errno", Observed::Null),
                Difference::check(54, "still held after one of two unlocks"),
                Difference::field(55, "pthread_mutex_unlock", "ret", Observed::Int(-1)),
                Difference::field(55, "pthread_mutex_unlock", "errno", Observed::Str("EPERM")),
                Difference::check(56, "unlock again"),
                Difference::field(69, "pthread_mutex_lock", "ret", Observed::Int(-1)),
                Difference::field(69, "pthread_mutex_lock", "errno", Observed::Str("EDEADLK")),
                Difference::check(70, "the owner relocks"),
                Difference::field(73, "pthread_mutex_unlock", "ret", Observed::Int(-1)),
                Difference::field(73, "pthread_mutex_unlock", "errno", Observed::Str("EPERM")),
                Difference::check(74, "unlock again"),
            ]),
        },
    ],
    ..DEFAULTS
};
