//! thread/lifecycle — glibc's thread lifecycle (nptl): `pthread_create`
//! runs the start routine on a new thread and `pthread_join` hands back
//! its return value; a detached
//! thread is not joinable and cannot be detached again (`EINVAL`, both
//! checked while it still runs, the only time its handle is valid);
//! `pthread_once` runs its routine exactly once, and a thread calling it
//! while another runs the routine waits until the routine returns; `pthread_getname_np` reads the thread's kernel name (`comm`, which a
//! thread inherits from its creator and the main thread takes from the
//! executable's basename, truncated to 15 bytes), refusing a buffer
//! shorter than `TASK_COMM_LEN` with `ERANGE`; and `pthread_cancel` of a
//! thread asleep in a cancellation point (`nanosleep`) ends it there, its
//! join answering `PTHREAD_CANCELED`.
//!
//! pthread functions return the error number rather than setting `errno`;
//! each is recorded as `-error` on failure. A libc-only subject, so the
//! libc vehicle alone.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use crate::signals as support;

unsafe extern "C" {
    fn pthread_getname_np(thread: pthread_t, name: *mut c_char, len: size_t) -> c_int;
    fn pthread_cancel(thread: pthread_t) -> c_int;
    /// glibc's `pthread_once_t` is an `int` (`PTHREAD_ONCE_INIT` 0).
    fn pthread_once(control: *mut c_int, routine: extern "C" fn()) -> c_int;
}

/// A pthread call's error number as the kernel convention (`-error`).
fn code(error: c_int) -> i64 {
    -(error as i64)
}

fn recorded(p: &Probe, op: &str, error: c_int) -> i64 {
    let result = code(error);
    p.rec.event(op, result).emit();
    result
}

/// glibc's `PTHREAD_CANCELED`, `(void *) -1`.
const CANCELED: usize = usize::MAX;

type Start = extern "C" fn(*mut c_void) -> *mut c_void;

fn create(p: &Probe, start: Start, arg: usize) -> (i64, pthread_t) {
    let mut thread: pthread_t = 0;
    // SAFETY: `start` is a valid start routine and `thread` is writable.
    let error = unsafe { pthread_create(&mut thread, null(), start, arg as *mut c_void) };
    (recorded(p, "pthread_create", error), thread)
}

/// Join `thread`, recording the result and the value it answered.
fn join(p: &Probe, thread: pthread_t, target: &str) -> (i64, usize) {
    let mut value: *mut c_void = null_mut();
    // SAFETY: `thread` is a handle this scenario created (or itself).
    let error = unsafe { pthread_join(thread, &mut value) };
    let result = code(error);
    p.rec
        .event("pthread_join", result)
        .arg("target", target)
        .field("value", value as usize)
        .emit();
    (result, value as usize)
}

extern "C" fn successor(arg: *mut c_void) -> *mut c_void {
    (arg as usize + 1) as *mut c_void
}

static STARTED: AtomicBool = AtomicBool::new(false);
static RELEASED: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);

/// Runs until released: a thread whose handle stays valid while the main
/// thread detaches and joins it.
extern "C" fn held(_: *mut c_void) -> *mut c_void {
    STARTED.store(true, Ordering::SeqCst);
    while !RELEASED.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
    DONE.store(true, Ordering::SeqCst);
    null_mut()
}

/// Sleeps in `nanosleep`, a cancellation point, until released, then
/// answers 7. `C-unwind` with no destructor in its frame: cancellation
/// unwinds through it (glibc's forced unwind).
extern "C-unwind" fn cancellable(_: *mut c_void) -> *mut c_void {
    STARTED.store(true, Ordering::SeqCst);
    let pause = timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    while !RELEASED.load(Ordering::SeqCst) {
        // SAFETY: a valid request and no remainder.
        unsafe { nanosleep(&pause, null_mut()) };
    }
    7 as *mut c_void
}

static ONCE_RUNS: AtomicUsize = AtomicUsize::new(0);
static mut ONCE: c_int = 0;

extern "C" fn once_routine() {
    ONCE_RUNS.fetch_add(1, Ordering::SeqCst);
}

fn once(p: &Probe) -> i64 {
    // SAFETY: the once control lives for the process; glibc (or the shim)
    // serializes access to it.
    recorded(p, "pthread_once", unsafe {
        pthread_once(&raw mut ONCE, once_routine)
    })
}

static HELD_RUNS: AtomicUsize = AtomicUsize::new(0);
static mut HELD_ONCE: c_int = 0;

/// A once routine that holds until released.
extern "C" fn held_routine() {
    HELD_RUNS.fetch_add(1, Ordering::SeqCst);
    STARTED.store(true, Ordering::SeqCst);
    while !RELEASED.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn held_once() -> c_int {
    // SAFETY: as in `once`.
    unsafe { pthread_once(&raw mut HELD_ONCE, held_routine) }
}

/// One worker runs a held once routine; a second worker's `pthread_once`
/// on the same control must wait until the routine returns.
fn contended_once(p: &Probe) {
    reset();
    let waiter_tid = AtomicI32::new(0);
    let returned = AtomicBool::new(false);
    let (runner, waiter) = std::thread::scope(|scope| {
        let runner = scope.spawn(held_once);
        let _release = support::Release(&RELEASED);
        wait_started(p);
        let waiter = scope.spawn(|| {
            waiter_tid.store(support::gettid(), Ordering::SeqCst);
            let error = held_once();
            returned.store(true, Ordering::SeqCst);
            error
        });
        p.rec.quiet(|| {
            support::wait_until(Duration::from_millis(1), || {
                waiter_tid.load(Ordering::SeqCst) != 0
            });
            support::until_parked(waiter_tid.load(Ordering::SeqCst));
        });
        p.check(
            "a concurrent pthread_once waits while the routine runs",
            !returned.load(Ordering::SeqCst),
        );
        RELEASED.store(true, Ordering::SeqCst);
        (
            runner.join().expect("the runner"),
            waiter.join().expect("the waiter"),
        )
    });
    p.rec
        .event("pthread_once", code(runner))
        .arg("by", "runner")
        .emit();
    p.rec
        .event("pthread_once", code(waiter))
        .arg("by", "waiter")
        .emit();
    p.check(
        "both return 0 once the routine has run, once",
        runner == 0 && waiter == 0 && HELD_RUNS.load(Ordering::SeqCst) == 1,
    );
}

fn getname(p: &Probe, len: usize) -> i64 {
    let mut name = [0 as c_char; 32];
    // SAFETY: `name` holds `len` <= 32 bytes.
    let error = unsafe { pthread_getname_np(pthread_self(), name.as_mut_ptr(), len) };
    let result = code(error);
    let text = if error == 0 {
        // SAFETY: on success glibc wrote a NUL-terminated name.
        unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    p.rec
        .event("pthread_getname_np", result)
        .arg("len", len)
        .field("name", text)
        .emit();
    result
}

fn wait_started(p: &Probe) {
    p.rec
        .quiet(|| support::wait_until(Duration::from_millis(1), || STARTED.load(Ordering::SeqCst)));
    p.require("the worker started", STARTED.load(Ordering::SeqCst));
}

fn reset() {
    STARTED.store(false, Ordering::SeqCst);
    RELEASED.store(false, Ordering::SeqCst);
    DONE.store(false, Ordering::SeqCst);
}

pub fn run(p: &Probe) {
    let (created, worker) = create(p, successor, 41);
    p.require("pthread_create", created == 0);
    let (joined, value) = join(p, worker, "worker");
    p.check(
        "join answers the start routine's return value",
        joined == 0 && value == 42,
    );

    reset();
    let (created, worker) = create(p, held, 0);
    p.require("pthread_create", created == 0);
    wait_started(p);
    p.check(
        "pthread_detach of a joinable thread",
        // SAFETY: the worker is held, so its handle is valid.
        recorded(p, "pthread_detach", unsafe { pthread_detach(worker) }) == 0,
    );
    let (joined, _) = join(p, worker, "detached");
    p.check("a detached thread is not joinable", joined == neg(EINVAL));
    p.check(
        "a detached thread cannot be detached again",
        // SAFETY: the worker is still held.
        recorded(p, "pthread_detach", unsafe { pthread_detach(worker) }) == neg(EINVAL),
    );
    RELEASED.store(true, Ordering::SeqCst);
    p.rec
        .quiet(|| support::wait_until(Duration::from_millis(1), || DONE.load(Ordering::SeqCst)));
    p.require("the detached worker finished", DONE.load(Ordering::SeqCst));

    p.check("pthread_once", once(p) == 0);
    p.check("pthread_once again", once(p) == 0);
    p.check(
        "the once routine ran exactly once",
        ONCE_RUNS.load(Ordering::SeqCst) == 1,
    );
    contended_once(p);

    p.check("pthread_getname_np of the main thread", getname(p, 16) == 0);
    let on_worker =
        std::thread::scope(|scope| scope.spawn(|| getname(p, 16)).join().expect("the worker"));
    p.check(
        "pthread_getname_np on a new thread: its creator's name",
        on_worker == 0,
    );
    p.check(
        "a buffer shorter than TASK_COMM_LEN is ERANGE",
        getname(p, 15) == neg(ERANGE),
    );

    reset();
    // SAFETY: a `C-unwind` start routine has the `extern "C"` routine's
    // calling convention; only the unwinding contract differs.
    let start: Start = unsafe {
        std::mem::transmute::<extern "C-unwind" fn(*mut c_void) -> *mut c_void, Start>(cancellable)
    };
    let (created, worker) = create(p, start, 0);
    p.require("pthread_create", created == 0);
    wait_started(p);
    // SAFETY: the worker is joinable and running.
    let canceled = recorded(p, "pthread_cancel", unsafe { pthread_cancel(worker) });
    p.check("pthread_cancel of a running thread", canceled == 0);
    if canceled != 0 {
        // A thread the cancel refused is released to finish on its own.
        RELEASED.store(true, Ordering::SeqCst);
    }
    let (joined, value) = join(p, worker, "canceled");
    p.check(
        "it ends at its next cancellation point, joined as PTHREAD_CANCELED",
        joined == 0 && value == CANCELED,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/lifecycle",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_clone3, Syscall::N_futex],
    symbols: &[
        "pthread_create",
        "pthread_join",
        "pthread_detach",
        "pthread_once",
        "pthread_getname_np",
        "pthread_cancel",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: &[Vehicle::Libc],
            what: "the shim's pthread_getname_np (c/posix/thread_sync.c) answers an empty name for every thread and buffer: no thread name is modeled (the main thread's is the executable's basename, and a new thread inherits its creator's), and a buffer shorter than TASK_COMM_LEN succeeds instead of ERANGE",
            failure: Failure::Differs(&[
                Difference::field(19, "pthread_getname_np", "fields.name", Observed::Str("")),
                Difference::field(21, "pthread_getname_np", "fields.name", Observed::Str("")),
                Difference::field(23, "pthread_getname_np", "ret", Observed::Int(0)),
                Difference::field(23, "pthread_getname_np", "errno", Observed::Null),
                Difference::check(24, "a buffer shorter than TASK_COMM_LEN is ERANGE"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: &[Vehicle::Libc],
            what: "the shim's pthread_cancel (c/posix/thread_sync.c) is a fail-closed ENOSYS: cancellation is not modeled, so the worker is never canceled at its cancellation point and, released, returns its own value",
            failure: Failure::Differs(&[
                Difference::field(26, "pthread_cancel", "ret", Observed::Int(-1)),
                Difference::field(26, "pthread_cancel", "errno", Observed::Str("ENOSYS")),
                Difference::check(27, "pthread_cancel of a running thread"),
                Difference::field(28, "pthread_join", "fields.value", Observed::Int(7)),
                Difference::check(
                    29,
                    "it ends at its next cancellation point, joined as PTHREAD_CANCELED",
                ),
            ]),
        },
    ],
    ..DEFAULTS
};
