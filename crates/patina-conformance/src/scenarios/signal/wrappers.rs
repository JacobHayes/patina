//! signal/wrappers — what glibc's signal wrappers add over the rows they
//! issue (the rows themselves are `signal/mask`, `signal/queue`,
//! `signal/wait` and `signal/block`, through `syscall(2)`):
//!
//! * `raise` is a thread-directed kill of the caller (`tgkill`, `SI_TKILL`)
//!   delivered before it returns, and a signal past `SIGRTMAX` is `EINVAL`;
//!   `__libc_current_sigrtmax` is 64;
//! * `sigprocmask` blocks with glibc's `sigset_t`, answering the previous
//!   mask, and an unknown `how` is `EINVAL`; `sigpending` reports what the
//!   mask holds back;
//! * the synchronous dequeues: `sigtimedwait` (and `sigwaitinfo` over it)
//!   folds the kernel's `SI_TKILL` into `SI_USER` (sysdeps/unix/sysv/linux/
//!   sigtimedwait.c), so a raised signal reads as sent by `kill`; with
//!   nothing pending a zero timeout is `EAGAIN`; `sigqueue` sends `SI_QUEUE`
//!   with its value from the caller's own pid and uid (the parent's pid is
//!   recorded first, so a sender naming it reads as such); `sigwait` answers the
//!   signal number;
//! * `sigsuspend` runs the handler of a signal its mask unblocks, answers
//!   `EINTR` and restores the mask;
//! * `siginterrupt` clears `SA_RESTART` (1) or sets it (0) on the installed
//!   action, keeping its handler and `SA_SIGINFO`, and refuses signal 0
//!   (`EINVAL`); `signal` installs with `SA_RESTART` and the signal blocked
//!   in its handler, but without `SA_RESTART` once `siginterrupt(sig, 1)`
//!   has named the signal (signal/sigintr.c `_sigintr`);
//! * the reserved signals SIGCANCEL (32) and SIGSETXID (33): `sigprocmask`
//!   never blocks them, and `sigaction`, `signal`, `siginterrupt` (through
//!   `__sigaction`) and `raise` (through `__pthread_kill`) refuse them
//!   (`EINVAL`);
//! * `killpg(0, sig)` signals the caller's own process group (`SI_USER`),
//!   and a negative group is `EINVAL`.
//!
//! A libc-only subject, so the libc vehicle alone. The native run is its
//! own process group (the harness spawns it so), which `killpg` requires.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::observe::{Id, Norm};
use crate::probe::{Probe, neg};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::Ordering;

use crate::signals as support;

unsafe extern "C" {
    fn siginterrupt(sig: c_int, flag: c_int) -> c_int;
}

fn recorded(p: &Probe, op: &str, sig: c_int, result: c_int) -> i64 {
    let result = fold_errno(result as i64);
    p.rec.event(op, result).arg("sig", sig).emit();
    result
}

fn raise_(p: &Probe, sig: c_int) -> i64 {
    // SAFETY: raising a handled, blocked or invalid signal.
    recorded(p, "raise", sig, unsafe { raise(sig) })
}

fn sigprocmask_(p: &Probe, how: c_int, set: Option<&sigset_t>) -> (i64, sigset_t) {
    let mut old = support::empty_set();
    // SAFETY: valid sets.
    let result =
        fold_errno(
            unsafe { sigprocmask(how, set.map_or(std::ptr::null(), |s| s), &mut old) } as i64,
        );
    p.rec
        .event("sigprocmask", result)
        .arg("how", how)
        .field("old_usr1", support::has(&old, SIGUSR1))
        .field("old_usr2", support::has(&old, SIGUSR2))
        .emit();
    (result, old)
}

fn sigpending_(p: &Probe) -> sigset_t {
    let mut set = support::empty_set();
    // SAFETY: a writable set.
    let result = fold_errno(unsafe { sigpending(&mut set) } as i64);
    p.rec
        .event("sigpending", result)
        .field("usr1", support::has(&set, SIGUSR1))
        .field("usr2", support::has(&set, SIGUSR2))
        .emit();
    set
}

/// Record a dequeue's answer and its siginfo sender fields.
fn dequeued(p: &Probe, op: &str, result: i64, info: &siginfo_t) -> i64 {
    // SAFETY: the kernel filled a siginfo for a dequeued signal; the sender
    // fields and value are read only then.
    let (pid, uid, value) = if result > 0 {
        unsafe {
            (
                info.si_pid(),
                info.si_uid(),
                info.si_value().sival_ptr as usize as i32,
            )
        }
    } else {
        (0, 0, 0)
    };
    p.rec
        .event(op, result)
        .field("si_signo", info.si_signo)
        .field("si_code", info.si_code)
        .field("si_pid", pid)
        .norm("fields.si_pid", Norm::Identity(Id::Process))
        .field("si_uid", uid)
        .norm("fields.si_uid", Norm::Identity(Id::User))
        .field("si_int", if info.si_code == SI_QUEUE { value } else { 0 })
        .emit();
    result
}

fn sigtimedwait_(p: &Probe, set: &sigset_t) -> (i64, siginfo_t) {
    // SAFETY: all-zero is a valid siginfo_t.
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    let zero = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid set, info and timeout.
    let result = fold_errno(unsafe { sigtimedwait(set, &mut info, &zero) } as i64);
    (dequeued(p, "sigtimedwait", result, &info), info)
}

/// What `sig`'s installed action holds, as `sigaction` reports it.
struct Action {
    restart: bool,
    siginfo: bool,
    /// Whether the action's mask blocks `sig` itself.
    mask_self: bool,
    handler: &'static str,
}

fn action(sig: c_int) -> Action {
    // SAFETY: a query into a zeroed action.
    let action = unsafe {
        let mut action: sigaction = std::mem::zeroed();
        assert_eq!(sigaction(sig, std::ptr::null(), &mut action), 0);
        action
    };
    let info =
        support::info_handler as unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void) as usize;
    let plain = support::handler as extern "C" fn(c_int) as usize;
    Action {
        restart: action.sa_flags & SA_RESTART != 0,
        siginfo: action.sa_flags & SA_SIGINFO != 0,
        mask_self: support::has(&action.sa_mask, sig),
        handler: match action.sa_sigaction {
            SIG_DFL => "SIG_DFL",
            SIG_IGN => "SIG_IGN",
            handler if handler == info => "info_handler",
            handler if handler == plain => "handler",
            _ => "other",
        },
    }
}

/// Record `op`'s result and, when it succeeded, the action it left.
fn with_action(p: &Probe, op: &str, sig: c_int, result: i64) -> Option<Action> {
    let builder = p.rec.event(op, result).arg("sig", sig);
    if result != 0 {
        builder.emit();
        return None;
    }
    let state = action(sig);
    builder
        .field("restart", state.restart)
        .field("siginfo", state.siginfo)
        .field("mask_self", state.mask_self)
        .field("handler", state.handler)
        .emit();
    Some(state)
}

fn siginterrupt_(p: &Probe, sig: c_int, flag: c_int) -> (i64, Option<Action>) {
    // SAFETY: plain values.
    let result = fold_errno(unsafe { siginterrupt(sig, flag) } as i64);
    let op = if flag == 0 {
        "siginterrupt(0)"
    } else {
        "siginterrupt(1)"
    };
    (result, with_action(p, op, sig, result))
}

/// glibc's `signal(sig, handler)`, the support crate's plain handler.
fn signal_(p: &Probe, sig: c_int) -> (i64, Option<Action>) {
    let plain = support::handler as extern "C" fn(c_int) as sighandler_t;
    // SAFETY: installs a handler that only counts.
    let old = unsafe { signal(sig, plain) };
    let result = if old == SIG_ERR {
        neg(crate::vehicle::errno())
    } else {
        0
    };
    (result, with_action(p, "signal", sig, result))
}

fn sigwaitinfo_(p: &Probe, set: &sigset_t) -> (i64, siginfo_t) {
    // SAFETY: all-zero is a valid siginfo_t.
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: a valid set and info.
    let result = fold_errno(unsafe { sigwaitinfo(set, &mut info) } as i64);
    (dequeued(p, "sigwaitinfo", result, &info), info)
}

/// Whether `set` holds `sig`, read from the kernel's bit: glibc's
/// `sigismember` (like `sigaddset`) refuses its reserved signals.
fn raw_has(set: &sigset_t, sig: c_int) -> bool {
    // SAFETY: the first word of a sigset_t holds signals 1..=64.
    let word = unsafe { *(set as *const sigset_t).cast::<u64>() };
    word & (1 << (sig - 1)) != 0
}

/// glibc's reserved signals, SIGCANCEL (32) and SIGSETXID (33): its
/// `sigprocmask` never blocks them, and its `sigaction` and `signal`
/// refuse them.
fn reserved(p: &Probe) {
    let mut set = support::empty_set();
    // SAFETY: the first word of a sigset_t holds signals 1..=64.
    unsafe { *(&raw mut set).cast::<u64>() |= (1 << 31) | (1 << 32) };
    // SAFETY: a valid set.
    let blocked = fold_errno(unsafe { sigprocmask(SIG_BLOCK, &set, std::ptr::null_mut()) } as i64);
    let mut current = support::empty_set();
    // SAFETY: a query into a writable set.
    unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut current) };
    p.rec
        .event("sigprocmask", blocked)
        .arg("how", SIG_BLOCK)
        .arg("set", "{32, 33}")
        .field("blocked_32", raw_has(&current, 32))
        .field("blocked_33", raw_has(&current, 33))
        .emit();
    p.check(
        "sigprocmask leaves the reserved signals unblocked",
        blocked == 0 && !raw_has(&current, 32) && !raw_has(&current, 33),
    );
    // SAFETY: a valid set.
    unsafe { sigprocmask(SIG_UNBLOCK, &set, std::ptr::null_mut()) };

    // SAFETY: a query into a zeroed action.
    let queried = fold_errno(unsafe {
        let mut old: sigaction = std::mem::zeroed();
        sigaction(32, std::ptr::null(), &mut old)
    } as i64);
    p.rec.event("sigaction", queried).arg("sig", 32).emit();
    p.check("sigaction of signal 32 is EINVAL", queried == neg(EINVAL));
    let plain = support::handler as extern "C" fn(c_int) as sighandler_t;
    // SAFETY: installs a handler that only counts, if it installs at all.
    let installed = if unsafe { signal(33, plain) } == SIG_ERR {
        neg(crate::vehicle::errno())
    } else {
        0
    };
    p.rec.event("signal", installed).arg("sig", 33).emit();
    p.check("signal of signal 33 is EINVAL", installed == neg(EINVAL));
    if installed == 0 {
        // SAFETY: restores the default disposition (unrecorded cleanup).
        unsafe { signal(33, SIG_DFL) };
    }
    // SAFETY: changes at most signal 32's restart flag.
    let interrupted = fold_errno(unsafe { siginterrupt(32, 1) } as i64);
    p.rec
        .event("siginterrupt", interrupted)
        .arg("sig", 32)
        .emit();
    p.check(
        "siginterrupt of signal 32 is EINVAL",
        interrupted == neg(EINVAL),
    );
    p.check("raise of signal 33 is EINVAL", raise_(p, 33) == neg(EINVAL));
}

pub fn run(p: &Probe) {
    support::reset();
    support::install(SIGUSR1, SA_SIGINFO, true);
    support::install(SIGUSR2, SA_SIGINFO, true);
    p.getpid();
    p.getuid();
    p.getppid();
    let tid = support::gettid();

    // SAFETY: no arguments.
    let rtmax = unsafe { __libc_current_sigrtmax() };
    p.rec.event("__libc_current_sigrtmax", rtmax as i64).emit();
    p.check("__libc_current_sigrtmax is 64", rtmax == 64);

    p.check("raise(SIGUSR1)", raise_(p, SIGUSR1) == 0);
    p.check(
        "the handler ran before raise returned, on the caller",
        support::count() == 1 && support::HANDLER_TID.load(Ordering::SeqCst) == tid,
    );
    p.check(
        "raise is thread-directed: SI_TKILL",
        support::LAST_CODE.load(Ordering::SeqCst) == SI_TKILL,
    );
    p.check(
        "raise past SIGRTMAX is EINVAL",
        raise_(p, 65) == neg(EINVAL),
    );

    let both = support::set_of(&[SIGUSR1, SIGUSR2]);
    let (blocked, old) = sigprocmask_(p, SIG_BLOCK, Some(&both));
    p.check(
        "sigprocmask(SIG_BLOCK) answers the previous mask",
        blocked == 0 && !support::has(&old, SIGUSR1) && !support::has(&old, SIGUSR2),
    );
    p.check(
        "sigprocmask with an unknown how is EINVAL",
        sigprocmask_(p, 99, Some(&both)).0 == neg(EINVAL),
    );

    p.check("raise a blocked SIGUSR1", raise_(p, SIGUSR1) == 0);
    p.check("a blocked signal runs no handler", support::count() == 1);
    let pending = sigpending_(p);
    p.check(
        "sigpending reports it alone",
        support::has(&pending, SIGUSR1) && !support::has(&pending, SIGUSR2),
    );
    let (got, info) = sigtimedwait_(p, &support::one_set(SIGUSR1));
    p.check(
        "sigtimedwait dequeues it, SI_TKILL folded into SI_USER",
        got == SIGUSR1 as i64 && info.si_code == SI_USER,
    );
    p.check(
        "with nothing pending a zero timeout is EAGAIN",
        sigtimedwait_(p, &support::one_set(SIGUSR1)).0 == neg(EAGAIN),
    );
    p.check("raise a blocked SIGUSR1", raise_(p, SIGUSR1) == 0);
    let (got, info) = sigwaitinfo_(p, &support::one_set(SIGUSR1));
    p.check(
        "sigwaitinfo dequeues it, SI_TKILL folded into SI_USER",
        got == SIGUSR1 as i64 && info.si_code == SI_USER,
    );

    let value = sigval {
        sival_ptr: 7usize as *mut c_void,
    };
    p.check(
        "sigqueue(self, SIGUSR2, 7)",
        // SAFETY: a signal the caller blocks.
        recorded(p, "sigqueue", SIGUSR2, unsafe {
            sigqueue(getpid(), SIGUSR2, value)
        }) == 0,
    );
    let (result, info) = sigwaitinfo_(p, &support::one_set(SIGUSR2));
    p.check(
        "sigwaitinfo answers SI_QUEUE and the value",
        result == SIGUSR2 as i64
            && info.si_code == SI_QUEUE
            // SAFETY: a queued signal's value.
            && unsafe { info.si_value().sival_ptr } as usize == 7,
    );

    p.check("raise a blocked SIGUSR2", raise_(p, SIGUSR2) == 0);
    let mut sig: c_int = 0;
    // SAFETY: a valid set and output.
    let error = unsafe { sigwait(&support::one_set(SIGUSR2), &mut sig) };
    p.rec
        .event("sigwait", -(error as i64))
        .field("sig", sig)
        .emit();
    p.check(
        "sigwait answers the signal number",
        error == 0 && sig == SIGUSR2,
    );

    p.check("raise a blocked SIGUSR1", raise_(p, SIGUSR1) == 0);
    let empty = support::empty_set();
    // SAFETY: a valid mask; a pending signal it unblocks ends the wait.
    let result = fold_errno(unsafe { sigsuspend(&empty) } as i64);
    p.rec.event("sigsuspend", result).emit();
    p.check(
        "sigsuspend runs the handler of the signal it unblocks and is EINTR",
        result == neg(EINTR) && support::count() == 2,
    );
    let (_, current) = sigprocmask_(p, SIG_BLOCK, None);
    p.check(
        "sigsuspend restores the mask",
        support::has(&current, SIGUSR1) && support::has(&current, SIGUSR2),
    );

    let (result, state) = siginterrupt_(p, SIGUSR1, 1);
    p.check(
        "siginterrupt(SIGUSR1, 1) clears SA_RESTART, keeping the handler and SA_SIGINFO",
        result == 0
            && state.is_some_and(|s| !s.restart && s.siginfo && s.handler == "info_handler"),
    );
    let (result, state) = siginterrupt_(p, SIGUSR1, 0);
    p.check(
        "siginterrupt(SIGUSR1, 0) sets SA_RESTART",
        result == 0 && state.is_some_and(|s| s.restart && s.handler == "info_handler"),
    );
    p.check(
        "siginterrupt of signal 0 is EINVAL",
        siginterrupt_(p, 0, 1).0 == neg(EINVAL),
    );
    let (result, state) = signal_(p, SIGUSR2);
    p.check(
        "signal installs with SA_RESTART, blocking the signal in its handler",
        result == 0
            && state
                .is_some_and(|s| s.restart && !s.siginfo && s.mask_self && s.handler == "handler"),
    );
    // SAFETY: plain values (unrecorded: the following signal() shows it).
    unsafe { siginterrupt(SIGUSR2, 1) };
    let (result, state) = signal_(p, SIGUSR2);
    p.check(
        "after siginterrupt(sig, 1), signal installs without SA_RESTART",
        result == 0 && state.is_some_and(|s| !s.restart),
    );

    // SAFETY: no pointers.
    let own_group = unsafe { syscall(SYS_getpgid, 0) } == unsafe { syscall(SYS_getpid) };
    p.require("the run is its own process group", own_group);
    p.check(
        "killpg(0, SIGUSR1)",
        // SAFETY: a signal every member of the caller's group (itself) blocks.
        recorded(p, "killpg", SIGUSR1, unsafe { killpg(0, SIGUSR1) }) == 0,
    );
    let (got, info) = sigtimedwait_(p, &support::one_set(SIGUSR1));
    p.check(
        "it is pending for the caller, sent by kill (SI_USER)",
        got == SIGUSR1 as i64 && info.si_code == SI_USER,
    );
    p.check(
        "killpg of a negative group is EINVAL",
        // SAFETY: an invalid group.
        recorded(p, "killpg", 0, unsafe { killpg(-1, 0) }) == neg(EINVAL),
    );

    reserved(p);

    p.check(
        "nothing is left pending",
        !support::has(&sigpending_(p), SIGUSR1),
    );
    sigprocmask_(p, SIG_SETMASK, Some(&empty));
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/wrappers",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_getpid,
        Syscall::N_getuid,
        Syscall::N_getppid,
        Syscall::N_tgkill,
        Syscall::N_kill,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigpending,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_rt_sigqueueinfo,
        Syscall::N_rt_sigsuspend,
        Syscall::N_rt_sigaction,
    ],
    symbols: &[
        "getpid",
        "getuid",
        "getppid",
        "sigaction",
        "signal",
        "syscall",
        "__libc_current_sigrtmax",
        "raise",
        "sigprocmask",
        "sigpending",
        "sigtimedwait",
        "sigwaitinfo",
        "sigqueue",
        "sigwait",
        "sigsuspend",
        "siginterrupt",
        "killpg",
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::thread(SIGUSR1),
            Generation::thread(SIGUSR1),
            Generation::thread(SIGUSR1),
            Generation::process(SIGUSR2),
            Generation::thread(SIGUSR2),
            Generation::thread(SIGUSR1),
            Generation::process(SIGUSR1),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
