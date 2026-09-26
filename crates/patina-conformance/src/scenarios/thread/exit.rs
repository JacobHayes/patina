//! thread/exit — glibc's `pthread_exit` ends only the calling thread, from
//! anywhere in its start routine (nptl unwinds its frames), and its
//! argument is the value `pthread_join` answers; the rest of the start
//! routine never runs. The thread ends as a returning one does, in glibc's
//! order (nptl/pthread_create.c `start_thread`): the unwind runs its cleanup
//! handlers, then the thread-local destructors run, then the `pthread_key`
//! destructors, all before the join returns. An init routine `pthread_once`
//! runs that leaves through `pthread_exit` leaves the once control fresh
//! (nptl pthread_once.c's `clear_once_control` cleanup handler): the next
//! caller runs the init.
//!
//! Kept out of `thread/lifecycle`, whose checks all run on threads that
//! return.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::Probe;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static PAST_EXIT: AtomicBool = AtomicBool::new(false);

/// glibc's `struct _pthread_cleanup_buffer`: the cleanup record
/// `_pthread_cleanup_push` links into the calling thread's chain, which the
/// unwind runs as it leaves the frame holding it.
#[repr(C)]
struct CleanupBuffer {
    routine: Option<extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    canceltype: c_int,
    prev: *mut CleanupBuffer,
}

unsafe extern "C" {
    /// glibc's `pthread_once_t` is an `int` (`PTHREAD_ONCE_INIT` 0).
    fn pthread_once(control: *mut c_int, routine: extern "C" fn()) -> c_int;
    fn _pthread_cleanup_push(
        buffer: *mut CleanupBuffer,
        routine: extern "C" fn(*mut c_void),
        arg: *mut c_void,
    );
    fn _pthread_cleanup_pop(buffer: *mut CleanupBuffer, execute: c_int);
}

/// The teardown steps in the order they ran: each records its place (from 1)
/// and the value it was handed.
static STEP: AtomicUsize = AtomicUsize::new(0);
static CLEANUP_AT: AtomicUsize = AtomicUsize::new(0);
static CLEANUP_ARG: AtomicUsize = AtomicUsize::new(0);
static TLS_AT: AtomicUsize = AtomicUsize::new(0);
static TSD_AT: AtomicUsize = AtomicUsize::new(0);
static TSD_VALUE: AtomicUsize = AtomicUsize::new(0);

fn next_step() -> usize {
    STEP.fetch_add(1, Ordering::SeqCst) + 1
}

extern "C" fn cleanup(arg: *mut c_void) {
    CLEANUP_AT.store(next_step(), Ordering::SeqCst);
    CLEANUP_ARG.store(arg as usize, Ordering::SeqCst);
}

/// A thread-local whose destructor records its step.
struct TlsGuard;
impl Drop for TlsGuard {
    fn drop(&mut self) {
        TLS_AT.store(next_step(), Ordering::SeqCst);
    }
}
thread_local! {
    static GUARD: TlsGuard = const { TlsGuard };
}

extern "C" fn tsd_destructor(value: *mut c_void) {
    TSD_AT.store(next_step(), Ordering::SeqCst);
    TSD_VALUE.store(value as usize, Ordering::SeqCst);
}

/// The key whose value the worker sets, created by the main thread.
static KEY: AtomicUsize = AtomicUsize::new(0);

/// Exits one call deep with its argument plus one, holding a cleanup handler,
/// a thread-local with a destructor and a `pthread_key` value. `C-unwind`
/// with no destructor in either frame: glibc's `pthread_exit` unwinds through
/// them.
extern "C-unwind" fn exits(arg: *mut c_void) -> *mut c_void {
    GUARD.with(|_| {});
    // SAFETY: a key the main thread created.
    unsafe {
        pthread_setspecific(
            KEY.load(Ordering::SeqCst) as pthread_key_t,
            9 as *const c_void,
        )
    };
    let mut buffer = MaybeUninit::<CleanupBuffer>::uninit();
    // SAFETY: the buffer outlives the handler's registration: it is popped
    // below, or run and unlinked by the unwind leaving this frame.
    unsafe { _pthread_cleanup_push(buffer.as_mut_ptr(), cleanup, 5 as *mut c_void) };
    nested_exit(arg as usize + 1);
    PAST_EXIT.store(true, Ordering::SeqCst);
    // SAFETY: the buffer pushed above.
    unsafe { _pthread_cleanup_pop(buffer.as_mut_ptr(), 0) };
    null_mut()
}

#[inline(never)]
extern "C-unwind" fn nested_exit(value: usize) {
    // SAFETY: called on a thread pthread_create started.
    unsafe { pthread_exit(value as *mut c_void) }
}

static mut ONCE: c_int = 0;
static ONCE_RUNS: AtomicUsize = AtomicUsize::new(0);
static PAST_ONCE: AtomicBool = AtomicBool::new(false);

/// A once routine that ends its thread instead of returning.
extern "C-unwind" fn once_exits() {
    ONCE_RUNS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: called on a thread pthread_create started.
    unsafe { pthread_exit(3 as *mut c_void) }
}

extern "C" fn once_returns() {
    ONCE_RUNS.fetch_add(1, Ordering::SeqCst);
}

/// Runs `once_exits` through `pthread_once`. `C-unwind` with no destructor in
/// its frame, as `exits`.
extern "C-unwind" fn once_worker(_: *mut c_void) -> *mut c_void {
    // SAFETY: a `C-unwind` routine has the `extern "C"` one's calling
    // convention; only the unwinding contract differs.
    let routine =
        unsafe { std::mem::transmute::<extern "C-unwind" fn(), extern "C" fn()>(once_exits) };
    // SAFETY: the once control lives for the process.
    unsafe { pthread_once(&raw mut ONCE, routine) };
    PAST_ONCE.store(true, Ordering::SeqCst);
    null_mut()
}

/// A `C-unwind` start routine as `pthread_create` takes it.
fn start_routine(
    routine: extern "C-unwind" fn(*mut c_void) -> *mut c_void,
) -> extern "C" fn(*mut c_void) -> *mut c_void {
    // SAFETY: a `C-unwind` start routine has the `extern "C"` routine's
    // calling convention; only the unwinding contract differs.
    unsafe {
        std::mem::transmute::<
            extern "C-unwind" fn(*mut c_void) -> *mut c_void,
            extern "C" fn(*mut c_void) -> *mut c_void,
        >(routine)
    }
}

/// A once routine that exits leaves the control to the next caller.
fn exiting_once(p: &Probe) {
    let mut thread: pthread_t = 0;
    // SAFETY: a valid start routine and a writable handle.
    let error =
        unsafe { pthread_create(&mut thread, null(), start_routine(once_worker), null_mut()) };
    p.require("pthread_create", error == 0);
    let mut value: *mut c_void = null_mut();
    // SAFETY: a joinable thread this scenario created.
    let error = unsafe { pthread_join(thread, &mut value) };
    p.rec
        .event("pthread_join", -(error as i64))
        .arg("target", "once worker")
        .field("value", value as usize)
        .emit();
    // SAFETY: the once control lives for the process.
    let error = unsafe { pthread_once(&raw mut ONCE, once_returns) };
    p.rec
        .event("pthread_once", -(error as i64))
        .arg("after", "an init that exited")
        .field("runs", ONCE_RUNS.load(Ordering::SeqCst))
        .emit();
    p.check(
        "an init routine's pthread_exit ends its thread and leaves the control to the next caller",
        value as usize == 3
            && error == 0
            && ONCE_RUNS.load(Ordering::SeqCst) == 2
            && !PAST_ONCE.load(Ordering::SeqCst),
    );
}

pub fn run(p: &Probe) {
    let mut key: pthread_key_t = 0;
    // SAFETY: a writable key and a destructor for its values.
    let error = unsafe { pthread_key_create(&mut key, Some(tsd_destructor)) };
    p.require("pthread_key_create", error == 0);
    KEY.store(key as usize, Ordering::SeqCst);
    let mut thread: pthread_t = 0;
    // SAFETY: a valid start routine and a writable handle.
    let error =
        unsafe { pthread_create(&mut thread, null(), start_routine(exits), 41 as *mut c_void) };
    p.rec.event("pthread_create", -(error as i64)).emit();
    p.require("pthread_create", error == 0);
    let mut value: *mut c_void = null_mut();
    // SAFETY: a joinable thread this scenario created.
    let error = unsafe { pthread_join(thread, &mut value) };
    p.rec
        .event("pthread_join", -(error as i64))
        .arg("target", "worker")
        .field("value", value as usize)
        .emit();
    p.check(
        "join answers pthread_exit's argument",
        error == 0 && value as usize == 42,
    );
    p.check(
        "the start routine does not continue past pthread_exit",
        !PAST_EXIT.load(Ordering::SeqCst),
    );
    let at = |step: &AtomicUsize| step.load(Ordering::SeqCst);
    p.rec
        .event("teardown", 0)
        .field("cleanup", at(&CLEANUP_AT))
        .field("cleanup_arg", at(&CLEANUP_ARG))
        .field("tls", at(&TLS_AT))
        .field("tsd", at(&TSD_AT))
        .field("tsd_value", at(&TSD_VALUE))
        .emit();
    p.check(
        "the cleanup handler, then the thread-local and the pthread_key destructors run",
        (
            at(&CLEANUP_AT),
            at(&CLEANUP_ARG),
            at(&TLS_AT),
            at(&TSD_AT),
            at(&TSD_VALUE),
        ) == (1, 5, 2, 3, 9),
    );
    // SAFETY: the key created above, its thread gone.
    unsafe { pthread_key_delete(key) };
    exiting_once(p);
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/exit",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_clone3, Syscall::N_exit],
    symbols: &[
        "pthread_create",
        "pthread_join",
        "pthread_exit",
        "pthread_once",
    ],
    ..DEFAULTS
};
