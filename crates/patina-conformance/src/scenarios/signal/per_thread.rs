//! signal/per_thread — the state a single-threaded scenario cannot tell from a
//! process-global one: the signal mask, the private pending set and the
//! alternate stack are per THREAD (kernel: `task_struct.blocked`, `.pending`,
//! `.sas_ss_sp`), and a new thread inherits its creator's mask
//! (kernel/fork.c copy_process copies `blocked`). A worker blocking SIGUSR1
//! must not stop the main thread's own `kill(self)` from being handled before
//! it returns (complete_signal: the sender, the one thread not blocking it);
//! the main thread's `tgkill` to the blocking worker stays pending for the
//! worker alone — invisible to the main thread's `rt_sigpending` while the
//! main thread blocks it too, not delivered by the main thread's unmask —
//! and the worker's unmask delivers it on the worker; the main thread's
//! altstack is not the worker's. The two threads take turns (`phase`); only
//! the thread whose turn it is records events.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::signals as support;

use crate::probe::Probe;
use libc::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, SA_SIGINFO, true);
    let pid = p.getpid() as pid_t;
    let main_tid = p.gettid() as pid_t;
    let usr1 = support::one_set(SIGUSR1);
    let usr2 = support::one_set(SIGUSR2);
    p.check(
        "main blocks SIGUSR2 before spawning",
        p.rt_sigprocmask(SIG_BLOCK, Some(&usr2), None, 8) == 0,
    );

    let turns = support::Turns::default();
    let main_stack = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let tid = turns.worker_starts();
            let mut inherited = support::empty_set();
            p.check(
                "worker reads its initial mask",
                p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut inherited), 8) == 0,
            );
            p.check(
                "a new thread inherits its creator's mask (SIGUSR2 blocked, SIGUSR1 not)",
                support::has(&inherited, SIGUSR2) && !support::has(&inherited, SIGUSR1),
            );
            p.check(
                "worker blocks SIGUSR1 on its own thread",
                p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0,
            );
            turns.pass(1);

            turns.wait(p, 2);
            let mut stack: stack_t = unsafe { std::mem::zeroed() };
            p.check(
                "worker queries its altstack",
                p.sigaltstack(None, Some(&mut stack)) == 0,
            );
            // (Rust's std gives each spawned thread its own small altstack
            // for its stack-overflow guard, so "disabled" is not the fact;
            // "not the range the main thread just installed" is.)
            p.check(
                "the altstack the main thread installed is not the worker's",
                stack.ss_sp as usize != main_stack.load(Ordering::SeqCst),
            );
            p.check(
                "the main thread's tgkill is not delivered while the worker blocks it",
                support::count() == 1,
            );
            let mut pending = support::empty_set();
            p.check(
                "worker rt_sigpending",
                p.rt_sigpending(&mut pending, 8) == 0,
            );
            p.check(
                "it is pending for the worker",
                support::has(&pending, SIGUSR1),
            );
            turns.pass(3);

            turns.wait(p, 4);
            p.check(
                "worker unblocks SIGUSR1",
                p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0,
            );
            p.check(
                "the worker's unmask delivered its private pending signal before returning",
                support::count() == 2,
            );
            p.check(
                "on the worker",
                support::HANDLER_TID.load(Ordering::SeqCst) == tid,
            );
            p.check(
                "with SI_TKILL",
                support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
            );
            turns.pass(5);
        });
        // A failed check panics natively (`--strict`); releasing the worker
        // on the way out keeps the scope's join from hanging.
        let _release = turns.release_guard();

        p.require("the worker reached its first turn", turns.wait(p, 1));
        let mut mine = support::empty_set();
        p.check(
            "main reads its mask",
            p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut mine), 8) == 0,
        );
        p.check(
            "a block on another thread does not change this thread's mask",
            !support::has(&mine, SIGUSR1) && support::has(&mine, SIGUSR2),
        );
        p.check(
            "main kill(self, SIGUSR1) while the worker blocks it",
            p.kill(pid, SIGUSR1) == 0,
        );
        p.check(
            "it was handled before kill returned (the sender does not block it)",
            support::count() == 1,
        );
        p.check(
            "on the main thread",
            support::HANDLER_TID.load(Ordering::SeqCst) == main_tid,
        );
        let mut memory = vec![0u8; SIGSTKSZ];
        let installed = stack_t {
            ss_sp: memory.as_mut_ptr() as *mut _,
            ss_flags: 0,
            ss_size: memory.len(),
        };
        p.check(
            "main installs an altstack",
            p.sigaltstack(Some(&installed), None) == 0,
        );
        main_stack.store(memory.as_mut_ptr() as usize, Ordering::SeqCst);
        p.check(
            "main blocks SIGUSR1 too",
            p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, 8) == 0,
        );
        let worker = turns.worker_tid();
        p.check(
            "main tgkills the worker while both block SIGUSR1",
            p.tgkill(pid, worker, SIGUSR1) == 0,
        );
        let mut pending = support::empty_set();
        p.check("main rt_sigpending", p.rt_sigpending(&mut pending, 8) == 0);
        p.check(
            "the worker's pending signal is not in the main thread's pending set",
            !support::has(&pending, SIGUSR1),
        );
        p.check(
            "main unblocks SIGUSR1 while the worker still blocks",
            p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, 8) == 0,
        );
        p.check(
            "unblocking on the main thread delivers nothing (the signal is the worker's)",
            support::count() == 1,
        );
        turns.pass(2);

        p.require("the worker finished its second turn", turns.wait(p, 3));
        p.check(
            "nothing more was delivered meanwhile",
            support::count() == 1,
        );
        let mut still: stack_t = unsafe { std::mem::zeroed() };
        p.check(
            "main queries its altstack",
            p.sigaltstack(None, Some(&mut still)) == 0,
        );
        p.check(
            "the worker's sigaltstack calls left the main thread's altstack alone",
            still.ss_sp as usize == main_stack.load(Ordering::SeqCst)
                && still.ss_size == memory.len(),
        );
        turns.pass(4);

        p.require("the worker finished its last turn", turns.wait(p, 5));
        let disable = stack_t {
            ss_sp: std::ptr::null_mut(),
            ss_flags: SS_DISABLE,
            ss_size: 0,
        };
        p.check(
            "main disables its altstack",
            p.sigaltstack(Some(&disable), None) == 0,
        );
        drop(memory);
    });
    p.check(
        "exactly two handlers ran: one per thread",
        support::count() == 2,
    );
    p.check(
        "main unblocks SIGUSR2",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr2), None, 8) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/per_thread",
    run,
    covers: &[
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigpending,
        Syscall::N_sigaltstack,
        Syscall::N_kill,
        Syscall::N_tgkill,
    ],
    symbols: &[
        "getpid",
        "gettid",
        "tgkill",
        "kill",
        "sigaction",
        "sigaltstack",
        "syscall",
    ],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGUSR1), Generation::thread(SIGUSR1)],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
