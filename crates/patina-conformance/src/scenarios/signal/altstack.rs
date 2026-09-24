//! signal/altstack — `sigaltstack` state and its errno vocabulary (man 2
//! sigaltstack: ENOMEM below MINSIGSTKSZ, EINVAL for unknown flags, EPERM
//! while executing on the stack), and `SA_ONSTACK` delivery: the handler's
//! stack pointer lies inside the alternate stack, `sigaltstack(NULL, &cur)`
//! inside the handler reports `SS_ONSTACK`, and disabling it from there is
//! `EPERM`.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

static LO: AtomicUsize = AtomicUsize::new(0);
static HI: AtomicUsize = AtomicUsize::new(0);
static ON_ALT: AtomicBool = AtomicBool::new(false);
static INSIDE_FLAGS: AtomicI32 = AtomicI32::new(-1);
static INSIDE_DISABLE: AtomicI32 = AtomicI32::new(0);
const SS_AUTODISARM: c_int = 0x8000_0000u32 as c_int;

extern "C" fn onstack_handler(_: c_int) {
    let local = 0u8;
    let sp = &local as *const u8 as usize;
    ON_ALT.store(
        sp >= LO.load(Ordering::SeqCst) && sp < HI.load(Ordering::SeqCst),
        Ordering::SeqCst,
    );
    unsafe {
        let mut cur: stack_t = std::mem::zeroed();
        if sigaltstack(std::ptr::null(), &mut cur) == 0 {
            INSIDE_FLAGS.store(cur.ss_flags, Ordering::SeqCst);
        }
        let disable = stack_t {
            ss_sp: std::ptr::null_mut(),
            ss_flags: SS_DISABLE,
            ss_size: 0,
        };
        if sigaltstack(&disable, std::ptr::null_mut()) == -1 {
            INSIDE_DISABLE.store(*__errno_location(), Ordering::SeqCst);
        }
    }
}

fn install() {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = SA_ONSTACK;
        sa.sa_sigaction = onstack_handler as *const () as usize;
        assert_eq!(sigaction(SIGUSR1, &sa, std::ptr::null_mut()), 0);
    }
}

pub fn run(p: &Probe) {
    let mut old: stack_t = unsafe { std::mem::zeroed() };
    p.check(
        "query initial altstack",
        p.sigaltstack(None, Some(&mut old)) == 0,
    );
    p.check(
        "initial altstack flags are a known state",
        old.ss_flags & !(SS_DISABLE | SS_ONSTACK | SS_AUTODISARM) == 0,
    );

    let too_small = vec![0u8; MINSIGSTKSZ - 1];
    let small = stack_t {
        ss_sp: too_small.as_ptr() as *mut _,
        ss_flags: 0,
        ss_size: too_small.len(),
    };
    p.check(
        "altstack smaller than MINSIGSTKSZ is ENOMEM",
        p.sigaltstack(Some(&small), None) == neg(ENOMEM),
    );
    let bad_flags = stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0x4000,
        ss_size: 0,
    };
    p.check(
        "unknown sigaltstack flags are EINVAL",
        p.sigaltstack(Some(&bad_flags), None) == neg(EINVAL),
    );

    let mut stack = vec![0u8; SIGSTKSZ];
    LO.store(stack.as_mut_ptr() as usize, Ordering::SeqCst);
    HI.store(stack.as_mut_ptr() as usize + stack.len(), Ordering::SeqCst);
    let new = stack_t {
        ss_sp: stack.as_mut_ptr() as *mut _,
        ss_flags: 0,
        ss_size: stack.len(),
    };
    p.check(
        "install altstack",
        p.sigaltstack(Some(&new), Some(&mut old)) == 0,
    );
    let mut cur: stack_t = unsafe { std::mem::zeroed() };
    p.sigaltstack(None, Some(&mut cur));
    p.check(
        "installed altstack is enabled",
        cur.ss_flags & SS_DISABLE == 0,
    );
    p.check(
        "the query reports the installed range",
        cur.ss_sp as usize == LO.load(Ordering::SeqCst) && cur.ss_size == stack.len(),
    );
    install();
    p.kill(p.getpid() as pid_t, SIGUSR1);
    p.require(
        "SA_ONSTACK handler ran on the alternate stack (sp inside the range)",
        ON_ALT.load(Ordering::SeqCst),
    );
    p.check(
        "inside the handler sigaltstack reports SS_ONSTACK",
        INSIDE_FLAGS.load(Ordering::SeqCst) & SS_ONSTACK != 0,
    );
    p.check(
        "disabling the stack while on it is EPERM",
        INSIDE_DISABLE.load(Ordering::SeqCst) == EPERM,
    );
    p.sigaltstack(None, Some(&mut cur));
    p.check(
        "after the handler the stack is no longer in use",
        cur.ss_flags & SS_ONSTACK == 0,
    );

    let disable = stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: SS_DISABLE,
        ss_size: 0,
    };
    p.check(
        "disable altstack",
        p.sigaltstack(Some(&disable), Some(&mut old)) == 0,
    );
    p.check(
        "old_ss reports the stack that was disabled",
        old.ss_sp as usize == LO.load(Ordering::SeqCst) && old.ss_size == stack.len(),
    );
    p.sigaltstack(None, Some(&mut cur));
    p.check(
        "a disabled stack reports SS_DISABLE",
        cur.ss_flags & SS_DISABLE != 0,
    );
    let autodisarm = stack_t {
        ss_sp: stack.as_mut_ptr() as *mut _,
        ss_flags: SS_AUTODISARM,
        ss_size: stack.len(),
    };
    p.check(
        "SS_AUTODISARM is accepted",
        p.sigaltstack(Some(&autodisarm), None) == 0,
    );
    p.check("disable it again", p.sigaltstack(Some(&disable), None) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/altstack",
    run,
    covers: &[Syscall::N_sigaltstack, Syscall::N_kill, Syscall::N_getpid],
    symbols: &["kill", "getpid", "sigaction"],
    trace: Some(TraceFacts {
        generations: &[Generation::process(SIGUSR1)],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
