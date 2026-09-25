//! signal/one_wake — a process-directed signal interrupts exactly ONE thread:
//! the thread group leader when it does not block the signal, else a thread
//! that does not (kernel/signal.c complete_signal: `wants_signal(sig, p)` for
//! the task the pid names — the leader — then the other threads). A thread
//! parked in a blocking `read` that BLOCKS the signal is not disturbed: its
//! read neither fails `EINTR` nor returns early, and completes on the later
//! write. Then the roles swap: the main thread blocks the signal, and the
//! worker — the one thread left that does not (the killing helper blocks it
//! too) — is interrupted in its read, the handler running on the worker.
//! Helpers wait until the threads are asleep in their reads and mark the
//! stream before they kill. (Its trace facts also bound the recorded trace: a
//! generation that wakes more than one task fails, even when the extra task
//! silently re-parks.)

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::{Probe, neg};
use libc::*;
use std::sync::atomic::Ordering;

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, 0, false);
    let pid = p.getpid() as pid_t;
    let main_tid = p.gettid() as pid_t;
    let usr1 = support::one_set(SIGUSR1);
    let (r, a) = p.pipe2(0);
    p.require("pipe for the main thread", r == 0);
    let (r, b) = p.pipe2(0);
    p.require("pipe for the worker", r == 0);

    let turns = support::Turns::default();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            p.check("worker blocks SIGUSR1", p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0);
            let tid = turns.worker_starts();
            turns.pass(1);
            // Parked here across the first kill; only the main thread's
            // later write ends this read. Unrecorded, and reported in the
            // worker's next turn: the main thread is recording meanwhile,
            // and the stream's order must not depend on who runs first.
            let (n, data) = p.rec.quiet(|| p.read(b[0], 1));

            turns.wait(p, 3);
            p.check("a thread that blocks the signal is not disturbed: its read completes on the later write", n == 1 && data == b"w");
            p.check("and no handler ran on it", support::HANDLER_TID.load(Ordering::SeqCst) != tid);
            p.check("worker unblocks SIGUSR1", p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0);
            turns.pass(4);
            p.check("with the leader blocking it, the process-directed signal interrupts the worker's read", p.read(b[0], 1).0 == neg(EINTR));
            p.check("the handler ran on the worker", support::HANDLER_TID.load(Ordering::SeqCst) == tid && support::count() == 2);
            turns.pass(5);
        });
        let _release = turns.release_guard();

        p.require("the worker is set up", turns.wait(p, 1));
        let worker = turns.worker_tid();
        scope.spawn(move || {
            // First kill: both threads asleep in their reads.
            support::until_parked(main_tid);
            support::kill_when_parked(p, worker, pid, SIGUSR1);
        });
        p.check(
            "the leader's read is interrupted (it does not block the signal)",
            p.read(a[0], 1).0 == neg(EINTR),
        );
        p.check(
            "exactly one handler ran, on the main thread",
            support::count() == 1 && support::HANDLER_TID.load(Ordering::SeqCst) == main_tid,
        );
        p.check("main writes to the worker's pipe", p.write(b[1], b"w") == 1);

        p.check(
            "main blocks SIGUSR1",
            p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0,
        );
        turns.pass(3);
        p.require("the worker unblocked", turns.wait(p, 4));
        scope.spawn(move || {
            // The helper blocks the signal itself, so the worker is the
            // only thread left that wants it.
            unsafe {
                pthread_sigmask(SIG_BLOCK, &usr1, std::ptr::null_mut());
            }
            support::kill_when_parked(p, worker, pid, SIGUSR1);
        });
        p.require("the worker was interrupted", turns.wait(p, 5));
        let mut pending = support::empty_set();
        p.check("main rt_sigpending", p.rt_sigpending(&mut pending, 8) == 0);
        p.check(
            "the signal was delivered to the worker, not left pending for the blocking leader",
            !support::has(&pending, SIGUSR1),
        );
    });
    p.check("two handlers ran in all", support::count() == 2);
    p.check(
        "main unblocks SIGUSR1",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0,
    );
    p.check("nothing was pending for it", support::count() == 2);
    for fd in [a[0], a[1], b[0], b[1]] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/one_wake",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_pipe2,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigpending,
        Syscall::N_kill,
    ],
    symbols: &[
        "getpid",
        "gettid",
        "pipe2",
        "read",
        "write",
        "close",
        "kill",
        "sigaction",
        "pthread_sigmask",
        "syscall",
    ],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGUSR1), Generation::process(SIGUSR1)],
        max_wakes_per_generation: Some(1),
    }),
    ..DEFAULTS
};
