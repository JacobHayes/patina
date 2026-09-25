//! thread/exit — glibc's `pthread_exit` ends only the calling thread, from
//! anywhere in its start routine (nptl unwinds its frames), and its
//! argument is the value `pthread_join` answers; the rest of the start
//! routine never runs.
//!
//! Kept out of `thread/lifecycle` so its patina leg completes (and is
//! replayed and straced): `pthread_exit` is a named fatal under patina.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::Probe;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};

static PAST_EXIT: AtomicBool = AtomicBool::new(false);

/// Exits one call deep with its argument plus one. `C-unwind` with no
/// destructor in either frame: glibc's `pthread_exit` unwinds through them.
extern "C-unwind" fn exits(arg: *mut c_void) -> *mut c_void {
    nested_exit(arg as usize + 1);
    PAST_EXIT.store(true, Ordering::SeqCst);
    null_mut()
}

#[inline(never)]
extern "C-unwind" fn nested_exit(value: usize) {
    // SAFETY: called on a thread pthread_create started.
    unsafe { pthread_exit(value as *mut c_void) }
}

pub fn run(p: &Probe) {
    let mut thread: pthread_t = 0;
    // SAFETY: a `C-unwind` start routine has the `extern "C"` routine's
    // calling convention; only the unwinding contract differs.
    let start = unsafe {
        std::mem::transmute::<
            extern "C-unwind" fn(*mut c_void) -> *mut c_void,
            extern "C" fn(*mut c_void) -> *mut c_void,
        >(exits)
    };
    // SAFETY: a valid start routine and a writable handle.
    let error = unsafe { pthread_create(&mut thread, null(), start, 41 as *mut c_void) };
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
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/exit",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_clone3, Syscall::N_exit],
    symbols: &["pthread_create", "pthread_join", "pthread_exit"],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: &[Vehicle::Libc],
        what: "pthread_exit is a named fatal (patina-native-shim src/lib.rs patina_thread_exit: a managed thread must return from its body), so the worker's call aborts the run before any event",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina native shim fatal: pthread_exit is not supported by Patina's deterministic thread runtime",
        },
    }],
    ..DEFAULTS
};
