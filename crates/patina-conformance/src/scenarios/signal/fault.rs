//! signal/fault — the signal rows handed pointers the kernel cannot use
//! (kernel/signal.c, fs/signalfd.c, fs/select.c): each is `EFAULT`, and what
//! the call did before the copy stands:
//!
//! * `rt_sigaction`: an unreadable new action is `EFAULT` and installs
//!   nothing; an unwritable old action is `EFAULT` after the new one took;
//! * `rt_sigprocmask`: an unreadable new set is `EFAULT` and changes nothing;
//!   an unwritable old set is `EFAULT` after the new set took;
//! * `rt_sigtimedwait`: an unreadable set or timeout is `EFAULT`; an
//!   unwritable siginfo is `EFAULT` and has consumed the signal;
//! * `sigaltstack`: an unreadable new stack is `EFAULT`; an unwritable old
//!   one is `EFAULT` after the new one took;
//! * `rt_sigpending` into an unwritable set, `rt_sigsuspend` and `signalfd4`
//!   from an unreadable one, `rt_sigqueueinfo` from an unreadable siginfo and
//!   `pselect6` from an unreadable signal-mask argument are `EFAULT`;
//! * `ppoll` copies its signal mask in before it judges its descriptor count,
//!   and `pselect6` its signal-mask argument before its timeout.
//!
//! Its own scenario, because a door that dereferences the pointer itself
//! ends the whole run (and a crash loses the captured event stream). Raw
//! vehicles only: glibc's wrappers read and write these structures in user
//! space, where a bad pointer is a `SIGSEGV` natively.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// An address no mapping holds (the zero page).
const UNMAPPED: i64 = 1;

/// The kernel's `struct sigaction` (the same on x86_64 and arm64).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelAction {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: u64,
}

fn address<T>(value: &T) -> i64 {
    value as *const T as i64
}

fn out<T>(value: &mut T) -> i64 {
    value as *mut T as i64
}

pub fn run(p: &Probe) {
    let raw = |call: Syscall, args: [i64; 6]| p.call_observed(call, args);
    let action = |sig: c_int| {
        let mut old = KernelAction::default();
        raw(
            Syscall::N_rt_sigaction,
            [sig as i64, 0, out(&mut old), 8, 0, 0],
        );
        old
    };
    let blocked = || {
        let mut set = 0u64;
        raw(
            Syscall::N_rt_sigprocmask,
            [SIG_BLOCK as i64, 0, out(&mut set), 8, 0, 0],
        );
        set
    };
    let pending = || {
        let mut set = 0u64;
        raw(Syscall::N_rt_sigpending, [out(&mut set), 8, 0, 0, 0, 0]);
        set
    };
    let usr2 = 1u64 << (SIGUSR2 - 1);

    p.check(
        "rt_sigaction from an unreadable new action is EFAULT",
        raw(
            Syscall::N_rt_sigaction,
            [SIGUSR1 as i64, UNMAPPED, 0, 8, 0, 0],
        ) == neg(EFAULT),
    );
    p.check("and installs nothing", action(SIGUSR1).handler == SIG_DFL);
    let ignore = KernelAction {
        handler: SIG_IGN,
        ..KernelAction::default()
    };
    p.check(
        "rt_sigaction into an unwritable old action is EFAULT",
        raw(
            Syscall::N_rt_sigaction,
            [SIGUSR1 as i64, address(&ignore), UNMAPPED, 8, 0, 0],
        ) == neg(EFAULT),
    );
    p.check("after the new one took", action(SIGUSR1).handler == SIG_IGN);
    let default = KernelAction::default();
    raw(
        Syscall::N_rt_sigaction,
        [SIGUSR1 as i64, address(&default), 0, 8, 0, 0],
    );

    p.check(
        "rt_sigprocmask from an unreadable new set is EFAULT",
        raw(
            Syscall::N_rt_sigprocmask,
            [SIG_BLOCK as i64, UNMAPPED, 0, 8, 0, 0],
        ) == neg(EFAULT),
    );
    p.check("and changes nothing", blocked() & usr2 == 0);
    p.check(
        "rt_sigprocmask into an unwritable old set is EFAULT",
        raw(
            Syscall::N_rt_sigprocmask,
            [SIG_BLOCK as i64, address(&usr2), UNMAPPED, 8, 0, 0],
        ) == neg(EFAULT),
    );
    p.check("after the new set took", blocked() & usr2 != 0);
    p.check(
        "rt_sigpending into an unwritable set is EFAULT",
        raw(Syscall::N_rt_sigpending, [UNMAPPED, 8, 0, 0, 0, 0]) == neg(EFAULT),
    );

    let (pid, tid) = (p.getpid(), p.gettid());
    p.require(
        "a blocked SIGUSR2 is pending",
        raw(Syscall::N_tgkill, [pid, tid, SIGUSR2 as i64, 0, 0, 0]) == 0 && pending() & usr2 != 0,
    );
    let now = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    p.check(
        "rt_sigtimedwait from an unreadable set is EFAULT",
        raw(
            Syscall::N_rt_sigtimedwait,
            [UNMAPPED, 0, address(&now), 8, 0, 0],
        ) == neg(EFAULT),
    );
    p.check(
        "rt_sigtimedwait from an unreadable timeout is EFAULT",
        raw(
            Syscall::N_rt_sigtimedwait,
            [address(&usr2), 0, UNMAPPED, 8, 0, 0],
        ) == neg(EFAULT),
    );
    p.check(
        "rt_sigtimedwait into an unwritable siginfo is EFAULT",
        raw(
            Syscall::N_rt_sigtimedwait,
            [address(&usr2), UNMAPPED, address(&now), 8, 0, 0],
        ) == neg(EFAULT),
    );
    p.check("and has consumed the signal", pending() & usr2 == 0);
    raw(
        Syscall::N_rt_sigprocmask,
        [SIG_UNBLOCK as i64, address(&usr2), 0, 8, 0, 0],
    );

    p.check(
        "rt_sigsuspend from an unreadable set is EFAULT",
        raw(Syscall::N_rt_sigsuspend, [UNMAPPED, 8, 0, 0, 0, 0]) == neg(EFAULT),
    );
    p.check(
        "rt_sigqueueinfo from an unreadable siginfo is EFAULT",
        raw(
            Syscall::N_rt_sigqueueinfo,
            [pid, SIGUSR2 as i64, UNMAPPED, 0, 0, 0],
        ) == neg(EFAULT),
    );
    p.check(
        "signalfd4 from an unreadable set is EFAULT",
        raw(Syscall::N_signalfd4, [-1, UNMAPPED, 8, 0, 0, 0]) == neg(EFAULT),
    );
    p.check(
        "pselect6 from an unreadable signal-mask argument is EFAULT",
        raw(Syscall::N_pselect6, [0, 0, 0, 0, address(&now), UNMAPPED]) == neg(EFAULT),
    );
    p.check(
        "ppoll's unreadable signal mask is EFAULT before its descriptor count is judged",
        raw(
            Syscall::N_ppoll,
            [0, u32::MAX as i64, address(&now), UNMAPPED, 8, 0],
        ) == neg(EFAULT),
    );
    let invalid = timespec {
        tv_sec: 0,
        tv_nsec: -1,
    };
    p.check(
        "pselect6's unreadable signal-mask argument is EFAULT before its timeout is judged",
        raw(
            Syscall::N_pselect6,
            [0, 0, 0, 0, address(&invalid), UNMAPPED],
        ) == neg(EFAULT),
    );

    p.check(
        "sigaltstack from an unreadable new stack is EFAULT",
        raw(Syscall::N_sigaltstack, [UNMAPPED, 0, 0, 0, 0, 0]) == neg(EFAULT),
    );
    let memory = vec![0u8; 64 * 1024];
    let stack = stack_t {
        ss_sp: memory.as_ptr() as *mut c_void,
        ss_flags: 0,
        ss_size: memory.len(),
    };
    p.check(
        "sigaltstack into an unwritable old stack is EFAULT",
        raw(
            Syscall::N_sigaltstack,
            [address(&stack), UNMAPPED, 0, 0, 0, 0],
        ) == neg(EFAULT),
    );
    let mut now_stack = stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    raw(Syscall::N_sigaltstack, [0, out(&mut now_stack), 0, 0, 0, 0]);
    p.check(
        "after the new one took",
        now_stack.ss_sp == stack.ss_sp && now_stack.ss_size == stack.ss_size,
    );
    let disable = stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: SS_DISABLE,
        ss_size: 0,
    };
    raw(Syscall::N_sigaltstack, [address(&disable), 0, 0, 0, 0, 0]);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/fault",
    run,
    covers: &[
        Syscall::N_rt_sigaction,
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigpending,
        Syscall::N_rt_sigtimedwait,
        Syscall::N_rt_sigsuspend,
        Syscall::N_rt_sigqueueinfo,
        Syscall::N_signalfd4,
        Syscall::N_pselect6,
        Syscall::N_ppoll,
        Syscall::N_sigaltstack,
    ],
    vehicles: Vehicle::KERNEL,
    ..DEFAULTS
};
