//! signal/restorer — a handler that returns through the caller's own
//! restorer: a raw action with `SA_RESTORER` naming the scenario's stub (two
//! instructions: `rt_sigreturn`), as runtimes that bypass glibc's
//! `sigaction` install (Go's among them). The kernel builds the handler's
//! frame with the stub as its return address (arch/x86/kernel/signal_64.c
//! `x64_setup_rt_frame`; arch/arm64/kernel/signal.c `setup_return`), the
//! handler returns into it, and `rt_sigreturn` restores the interrupted
//! context from the frame — including the signal mask the handler edited in
//! it (`restore_sigcontext`, `set_current_blocked`): SIGUSR2, added to the
//! frame's `uc_sigmask` inside the handler, is blocked once the raise
//! returns, and SIGUSR1, blocked while its handler ran, is not.
//!
//! The action is installed and reported back raw (glibc's `sigaction` would
//! substitute its own restorer), so the scenario runs through the kernel
//! vehicles; `rt_sigreturn` itself is always the stub's own. On x86_64 the
//! stub is the `syscall` instruction. On
//! arm64 the stub tail-calls glibc's `syscall(2)`, which leaves the stack
//! (the frame) alone. A raw `svc` anywhere in the probe would make patina
//! refuse the whole binary on arm64, which has no syscall-user-dispatch; that
//! is also why the raw vehicle is x86_64-only.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{KernelSigaction, Probe, SA_RESTORER, SIGSET_BYTES};
use crate::signals as support;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

// The restorer: the handler returns into it with the frame on the stack,
// and it issues `rt_sigreturn`, which never returns.
#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    ".pushsection .text.patina_conformance_restorer,\"ax\",@progbits",
    ".globl patina_conformance_restorer",
    ".hidden patina_conformance_restorer",
    ".type patina_conformance_restorer,@function",
    "patina_conformance_restorer:",
    "mov eax, {rt_sigreturn}",
    "syscall",
    "ud2",
    ".size patina_conformance_restorer, . - patina_conformance_restorer",
    ".popsection",
    rt_sigreturn = const libc::SYS_rt_sigreturn,
);
#[cfg(target_arch = "aarch64")]
std::arch::global_asm!(
    ".pushsection .text.patina_conformance_restorer,\"ax\",%progbits",
    ".globl patina_conformance_restorer",
    ".hidden patina_conformance_restorer",
    ".type patina_conformance_restorer,%function",
    "patina_conformance_restorer:",
    "mov x0, #{rt_sigreturn}",
    "b syscall",
    ".size patina_conformance_restorer, . - patina_conformance_restorer",
    ".popsection",
    rt_sigreturn = const libc::SYS_rt_sigreturn,
);

unsafe extern "C" {
    fn patina_conformance_restorer();
}

/// Records the delivery, then adds SIGUSR2 to the mask the frame restores.
///
/// # Safety
///
/// Called by the kernel as a `SA_SIGINFO` handler: `context` is its frame's
/// `ucontext_t`.
unsafe extern "C" fn editing_handler(sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
    // SAFETY: the kernel's arguments to a SA_SIGINFO handler.
    unsafe {
        support::info_handler(sig, info, context);
        sigaddset(&mut (*context.cast::<ucontext_t>()).uc_sigmask, SIGUSR2);
    }
}

pub fn run(p: &Probe) {
    support::reset();
    let pid = p.getpid() as pid_t;
    let tid = p.gettid() as pid_t;
    let restorer = patina_conformance_restorer as unsafe extern "C" fn() as usize;
    let act = KernelSigaction {
        handler: editing_handler as unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void)
            as usize,
        flags: SA_SIGINFO as u64 | SA_RESTORER,
        restorer,
        mask: 0,
    };
    p.check(
        "a raw action with the caller's own restorer installs",
        p.rt_sigaction_install(SIGUSR1, Some(&act), None) == 0,
    );
    let (r, installed) = p.rt_sigaction_query(SIGUSR1);
    p.check(
        "the action reports the caller's restorer back",
        r == 0 && installed.flags & SA_RESTORER != 0 && installed.restorer == restorer,
    );
    p.check(
        "raising SIGUSR1 at itself",
        p.tgkill(pid, tid, SIGUSR1) == 0,
    );
    p.check(
        "the handler ran once, for the thread-directed SIGUSR1",
        support::count() == 1
            && support::LAST_SIG.load(std::sync::atomic::Ordering::SeqCst) == SIGUSR1
            && support::LAST_CODE.load(std::sync::atomic::Ordering::SeqCst) == SI_TKILL,
    );
    p.check(
        "SIGUSR1 was blocked while its handler ran",
        support::entry_masks() == [(true, false)],
    );
    let mut now = support::empty_set();
    p.require(
        "read the mask",
        p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut now), SIGSET_BYTES as usize) == 0,
    );
    p.check(
        "rt_sigreturn restored the frame's mask: SIGUSR2, added in the frame, is blocked",
        support::has(&now, SIGUSR2),
    );
    p.check(
        "and SIGUSR1 is unblocked again",
        !support::has(&now, SIGUSR1),
    );
    let usr2 = support::one_set(SIGUSR2);
    p.require(
        "unblock SIGUSR2",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr2), None, SIGSET_BYTES as usize) == 0,
    );
    let default = KernelSigaction::default();
    p.require(
        "restore SIGUSR1's default action",
        p.rt_sigaction_install(SIGUSR1, Some(&default), None) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/restorer",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_rt_sigreturn,
        Syscall::N_rt_sigaction,
        Syscall::N_tgkill,
        Syscall::N_rt_sigprocmask,
    ],
    ..DEFAULTS
};
