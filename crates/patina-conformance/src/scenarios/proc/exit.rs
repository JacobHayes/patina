//! proc/exit — the end of a process through glibc (stdlib/exit.c):
//!
//! * `exit` runs the `atexit` handlers in the reverse order of their
//!   registration, a handler registered while they run before the ones
//!   still pending, and the process then exits with the status given (3);
//! * `waitpid` (posix/waitpid.c) finds no child to reap (ECHILD); proc/wait
//!   holds the wait4 row itself, on every vehicle.
//!
//! The handlers record their own events after `exit` is called; the last
//! one checks the order and announces the status. glibc's `exit` also
//! flushes the stdio buffers after the handlers (`_IO_cleanup`); nothing
//! here observes that (the probe's standard output carries its event
//! stream), so a model that buffers the streams, as fd/stdio's gap asks,
//! must bring its own evidence of the flush at exit. libc only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, Ordering};

/// The probe the handlers record through (set before `exit`).
static PROBE: AtomicPtr<Probe> = AtomicPtr::new(std::ptr::null_mut());
/// The handlers in the order they ran.
static RAN: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn handler(which: u8) -> &'static Probe {
    // SAFETY: set from the scenario's own probe, which outlives `exit`.
    let p = unsafe { &*PROBE.load(Ordering::SeqCst) };
    RAN.lock().unwrap().push(which);
    p.rec
        .event("atexit_handler", 0)
        .arg("handler", which)
        .emit();
    p
}

extern "C" fn first() {
    let p = handler(1);
    let ran = RAN.lock().unwrap().clone();
    p.check(
        "handlers run last-registered first, a late one before the rest",
        ran == [3, 4, 2, 1],
    );
    p.exits_with(STATUS);
}

/// The status the scenario exits with.
const STATUS: c_int = 3;

extern "C" fn second() {
    handler(2);
}

extern "C" fn third() {
    handler(3);
    // SAFETY: registering a handler while the handlers run.
    let r = unsafe { atexit(late) };
    handler_probe()
        .rec
        .event("atexit", i64::from(r))
        .arg("handler", 4)
        .emit();
}

extern "C" fn late() {
    handler(4);
}

fn handler_probe() -> &'static Probe {
    // SAFETY: as in `handler`.
    unsafe { &*PROBE.load(Ordering::SeqCst) }
}

/// `waitpid(pid, options)`: the result and the status word.
fn wait(p: &Probe, pid: pid_t, options: c_int, pid_shown: &str) -> i64 {
    let mut status = 0;
    // SAFETY: a live status word.
    let r = fold_errno(i64::from(unsafe { waitpid(pid, &mut status, options) }));
    p.rec
        .event("waitpid", r)
        .arg("pid", pid_shown)
        .arg("options", options)
        .field("status", status)
        .emit();
    r
}

pub fn run(p: &Probe) {
    p.check(
        "waitpid without children is ECHILD",
        wait(p, -1, WNOHANG, "-1") == neg(ECHILD),
    );

    PROBE.store(std::ptr::from_ref(p).cast_mut(), Ordering::SeqCst);
    for (which, f) in [(1, first as extern "C" fn()), (2, second), (3, third)] {
        // SAFETY: registering a handler that outlives the process.
        let r = unsafe { atexit(f) };
        p.rec
            .event("atexit", i64::from(r))
            .arg("handler", which)
            .emit();
        p.check("atexit registers the handler", r == 0);
    }
    p.rec.event("exit", 0).arg("status", STATUS).emit();
    // SAFETY: the process ends here; the handlers above record the rest.
    unsafe { exit(STATUS) }
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/exit",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_wait4, Syscall::N_exit_group],
    symbols: &["waitpid", "exit"],
    ..DEFAULTS
};
