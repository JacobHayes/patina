//! signal/raw_restart_reexecutes_original_args — a call `SA_RESTART`
//! restarts runs again from its original arguments, which the handler may
//! have made stale (the kernel rewinds to the system call instruction): an
//! untimed `FUTEX_WAIT` for the value 0, interrupted by a handler that sets
//! the word to 1, is restarted and answers `EAGAIN`, the word no longer
//! holding the value it waits for.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::probe::{FUTEX_WAIT_PRIVATE, Probe, neg};
use crate::signals as support;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

/// The futex word the main thread waits on.
static WORD: AtomicU32 = AtomicU32::new(0);

extern "C" fn change_word(sig: c_int) {
    WORD.store(1, Ordering::SeqCst);
    support::handler(sig);
}

pub fn run(p: &Probe) {
    support::reset();
    WORD.store(0, Ordering::SeqCst);
    support::install_with(
        SIGUSR1,
        SA_RESTART,
        change_word as extern "C" fn(c_int) as usize,
    );
    let pid = p.getpid() as pid_t;
    let waited = thread::scope(|scope| {
        support::delayed_kills(scope, p, pid, &[SIGUSR1]);
        p.futex(&WORD, FUTEX_WAIT_PRIVATE, 0, None)
    });
    p.check(
        "the restarted FUTEX_WAIT finds the word changed and answers EAGAIN",
        waited == neg(EAGAIN),
    );
    p.check("the handler ran once", support::count() == 1);
    support::install_disposition(SIGUSR1, SIG_DFL);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/raw_restart_reexecutes_original_args",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_getpid, Syscall::N_kill, Syscall::N_futex],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGUSR1)],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
