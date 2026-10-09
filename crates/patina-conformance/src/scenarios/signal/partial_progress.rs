//! signal/partial_progress — a blocking transfer that a handler interrupts
//! after part of it moved answers what moved, even under `SA_RESTART`: the
//! kernel restarts only a call that transferred nothing (`pipe_write`'s
//! `if (!ret) ret = -ERESTARTSYS`).
//!
//! The helper, after its kill, waits for the call to return and then keeps
//! the other side moving (it drains the pipe to end-of-file); its wait is
//! bounded, so a call that wrongly restarts completes with the whole length
//! instead of hanging.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::probe::Probe;
use crate::signals as support;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Read `fd` until end-of-file, unobserved.
fn drain(fd: c_int) {
    let mut buf = [0u8; 4096];
    while unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
}

/// Once the main thread is parked, interrupt it; once its call returned (or
/// the bounded wait ends), run `then`.
fn interrupt_then(
    p: &Probe,
    main_tid: pid_t,
    pid: pid_t,
    returned: &AtomicBool,
    then: impl FnOnce(),
) {
    support::kill_when_parked(p, main_tid, pid, SIGUSR1);
    support::wait_until(Duration::from_millis(1), || returned.load(Ordering::SeqCst));
    then();
}

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, SA_RESTART, false);
    let pid = p.getpid() as pid_t;
    let main_tid = support::gettid();
    let big = vec![0x5a_u8; 100_000];

    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe", r == 0);
    let capacity = p.fcntl(wr, F_GETPIPE_SZ, 0);
    p.require("the pipe's capacity is below the write", (1..100_000).contains(&capacity));
    let returned = AtomicBool::new(false);
    let wrote = thread::scope(|scope| {
        scope.spawn(|| interrupt_then(p, main_tid, pid, &returned, || drain(rd)));
        let wrote = p.write(wr, &big);
        returned.store(true, Ordering::SeqCst);
        p.close(wr);
        wrote
    });
    p.check(
        "a pipe write a handler interrupts after it filled the pipe answers the bytes written",
        wrote == capacity,
    );
    p.close(rd);

    p.check(
        "the interrupted write ran the handler once",
        support::count() == 1,
    );
    support::install_disposition(SIGUSR1, SIG_DFL);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/partial_progress",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_pipe2,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_fcntl,
        Syscall::N_kill,
    ],
    symbols: &["getpid", "pipe2", "write", "close", "fcntl", "kill", "sigaction"],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGUSR1)],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
