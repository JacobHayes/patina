//! signal/default — default terminating actions are reported by wait status,
//! including WTERMSIG and the core-dump bit for core-action signals, through
//! a child made by glibc's `fork()`; and the `pthread_atfork` handlers
//! registered around it run (posix/register-atfork.c, nptl/fork.c): the
//! prepare handlers before the fork in reverse registration order, the
//! parent and child handlers after it in registration order, each on its
//! own side. A child that saw its handlers out of order exits 3 instead of
//! dying by its signal.
//!
//! The pin of the shim's diagnostic for glibc's `fork()` among the signal
//! and thread scenarios (the process class is a non-goal; `fs/fortify`
//! meets it too): under patina the registrations answer but the run stops
//! at the fork, so the child oracle and the handlers run natively only. The same deaths are compared in-process
//! through every vehicle by `signal/core_term`, `signal/handler_flags` and
//! `signal/pipe_term`, so this scenario has the libc vehicle only.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::Probe;
use crate::vehicle::fold_errno;
use libc::*;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

static LOG: [AtomicU8; 16] = [const { AtomicU8::new(0) }; 16];
static LOGGED: AtomicUsize = AtomicUsize::new(0);

fn log(mark: u8) {
    let slot = LOGGED.fetch_add(1, Ordering::SeqCst);
    if let Some(entry) = LOG.get(slot) {
        entry.store(mark, Ordering::SeqCst);
    }
}

/// The atfork handlers run so far, in order: `a`/`b` prepare, `A`/`B`
/// parent, `x`/`y` child, for the first and second registration.
fn logged() -> String {
    LOG[..LOGGED.load(Ordering::SeqCst).min(LOG.len())]
        .iter()
        .map(|entry| entry.load(Ordering::SeqCst) as char)
        .collect()
}

extern "C" fn prepare_a() {
    log(b'a');
}
extern "C" fn parent_a() {
    log(b'A');
}
extern "C" fn child_a() {
    log(b'x');
}
extern "C" fn prepare_b() {
    log(b'b');
}
extern "C" fn parent_b() {
    log(b'B');
}
extern "C" fn child_b() {
    log(b'y');
}

/// A child's exit code when it saw its atfork handlers out of order.
const OUT_OF_ORDER: c_int = 3;

fn child_signal(p: &Probe, sig: c_int) -> c_int {
    p.fork_child(
        || fold_errno(unsafe { fork() } as i64),
        || unsafe {
            if !logged().ends_with("baxy") {
                return OUT_OF_ORDER;
            }
            signal(sig, SIG_DFL);
            kill(getpid(), sig);
            99
        },
    )
    .wait()
}

fn register(p: &Probe, which: &str, handlers: [extern "C" fn(); 3]) -> i64 {
    let [prepare, parent, child] = handlers;
    // SAFETY: handlers that only log.
    let error = unsafe { pthread_atfork(Some(prepare), Some(parent), Some(child)) };
    let result = -(error as i64);
    p.rec
        .event("pthread_atfork", result)
        .arg("which", which)
        .emit();
    result
}

pub fn run(p: &Probe) {
    p.getpid();
    let first = register(p, "first", [prepare_a, parent_a, child_a]);
    let second = register(p, "second", [prepare_b, parent_b, child_b]);
    p.check(
        "pthread_atfork registers both sets",
        first == 0 && second == 0,
    );
    let term = child_signal(p, SIGTERM);
    let parent = logged();
    p.rec
        .event("atfork_handlers", 0)
        .field("parent", parent.as_str())
        .emit();
    p.check(
        "prepare handlers ran in reverse order, parent handlers in order",
        parent == "baAB",
    );
    p.check(
        "the child ran the prepare handlers, then its own, in order",
        !(WIFEXITED(term) && WEXITSTATUS(term) == OUT_OF_ORDER),
    );
    p.rec
        .event("wait_status", 0)
        .arg("case", "SIGTERM")
        .field("signaled", WIFSIGNALED(term))
        .field("termsig", WTERMSIG(term))
        .field("core", WCOREDUMP(term))
        .emit();
    p.check(
        "SIGTERM terminates with no core flag",
        WIFSIGNALED(term) && WTERMSIG(term) == SIGTERM && !WCOREDUMP(term),
    );

    let core = child_signal(p, SIGABRT);
    p.rec
        .event("wait_status", 0)
        .arg("case", "SIGABRT")
        .field("signaled", WIFSIGNALED(core))
        .field("termsig", WTERMSIG(core))
        .field("core", WCOREDUMP(core))
        .emit();
    p.check(
        "SIGABRT terminates and sets the core flag",
        WIFSIGNALED(core) && WTERMSIG(core) == SIGABRT && WCOREDUMP(core),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/default",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_getpid],
    symbols: &["getpid", "signal", "pthread_atfork"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: &[Vehicle::Libc],
        what: "fork is a process-lifecycle trap (docs/arcs/syscall-conformance.md §7); the child oracle runs natively only, and so do the atfork handlers: the shim's pthread_atfork (c/posix/thread_sync.c) answers the registration and drops the handlers, which only a fork could run",
        failure: Failure::Stops {
            events: 4,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: process spawn reached under patina: fork; the process class is a deterministic-runtime non-goal; failing closed",
        },
    }],
    ..DEFAULTS
};
