//! signal/raw_sigsuspend_frame_saved_mask — the mask a temporary-mask wait's
//! first signal frame saves (`sigmask_to_save`): with the thread blocking
//! SIGUSR1 and SIGUSR2 and SIGUSR1 pending, `rt_sigsuspend` under a mask
//! that blocks only SIGUSR2 runs SIGUSR1's handler, whose `uc_sigmask` is
//! the mask from before the suspension (SIGUSR1 blocked), not the temporary
//! one, while it runs under the temporary mask with SIGUSR1 added; the
//! suspension answers `EINTR` with the old mask back. With SIGUSR1 and
//! SIGUSR2 both pending and a temporary mask of SIGHUP alone, the kernel
//! builds SIGUSR1's frame first, saving the old mask, and SIGUSR2's over it,
//! saving the temporary mask with SIGUSR1's handler mask: SIGUSR2's handler
//! runs first.
//!
//! glibc's `sigsuspend` is the same row; the scenario runs through the kernel
//! vehicles.

use crate::catalog::{DEFAULTS, Generation, Scenario, TraceFacts};
use crate::probe::{Probe, neg};
use crate::signals as support;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicI32, Ordering};

/// Per handler run, in order: its signal, and SIGUSR1 (bit 0), SIGUSR2 (bit
/// 1) and SIGHUP (bit 2) in its frame's saved mask.
static SAVED: [AtomicI32; 2] = [const { AtomicI32::new(-1) }; 2];
static SIGNALLED: [AtomicI32; 2] = [const { AtomicI32::new(0) }; 2];

/// # Safety
/// `context` is the `ucontext_t` the kernel hands a `SA_SIGINFO` handler.
unsafe extern "C" fn record_frame(sig: c_int, _: *mut siginfo_t, context: *mut c_void) {
    let saved = unsafe { &(*context.cast::<ucontext_t>()).uc_sigmask };
    let index = support::count();
    if index < SAVED.len() {
        SAVED[index].store(
            i32::from(support::has(saved, SIGUSR1))
                | (i32::from(support::has(saved, SIGUSR2)) << 1)
                | (i32::from(support::has(saved, SIGHUP)) << 2),
            Ordering::SeqCst,
        );
        SIGNALLED[index].store(sig, Ordering::SeqCst);
    }
    support::handler(sig);
}

fn forget() {
    support::reset();
    for (saved, signalled) in SAVED.iter().zip(&SIGNALLED) {
        saved.store(-1, Ordering::SeqCst);
        signalled.store(0, Ordering::SeqCst);
    }
}

fn runs() -> Vec<(i32, i32)> {
    SIGNALLED
        .iter()
        .zip(&SAVED)
        .map(|(sig, saved)| (sig.load(Ordering::SeqCst), saved.load(Ordering::SeqCst)))
        .collect()
}

pub fn run(p: &Probe) {
    forget();
    let recorder = record_frame as unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void);
    support::install_with(SIGUSR1, SA_SIGINFO, recorder as usize);
    support::install_with(SIGUSR2, SA_SIGINFO, recorder as usize);
    let both = support::set_of(&[SIGUSR1, SIGUSR2]);
    let mut before = support::empty_set();
    p.require(
        "block SIGUSR1 and SIGUSR2",
        p.rt_sigprocmask(SIG_SETMASK, Some(&both), Some(&mut before), 8) == 0,
    );
    let (pid, tid) = (p.getpid() as pid_t, p.gettid() as pid_t);
    p.check(
        "SIGUSR1 is left pending",
        p.tgkill(pid, tid, SIGUSR1) == 0 && support::count() == 0,
    );
    let temporary = support::one_set(SIGUSR2);
    p.check(
        "rt_sigsuspend under a mask that releases SIGUSR1 is EINTR",
        p.rt_sigsuspend(&temporary, 8) == neg(EINTR),
    );
    p.check("SIGUSR1's handler ran once", support::count() == 1);
    p.check(
        "its frame saved the mask from before the suspension",
        runs()[0] == (SIGUSR1, 0b011),
    );
    p.check(
        "it ran under the temporary mask with SIGUSR1 added",
        support::entry_masks().first() == Some(&(true, true)),
    );
    let mut after = support::empty_set();
    p.check(
        "the suspension returned with the old mask",
        p.rt_sigprocmask(SIG_BLOCK, None, Some(&mut after), 8) == 0
            && support::has(&after, SIGUSR1)
            && support::has(&after, SIGUSR2),
    );

    forget();
    let all = support::set_of(&[SIGUSR1, SIGUSR2, SIGHUP]);
    p.require(
        "block SIGUSR1, SIGUSR2 and SIGHUP",
        p.rt_sigprocmask(SIG_SETMASK, Some(&all), None, 8) == 0,
    );
    p.check(
        "SIGUSR1 and SIGUSR2 are left pending",
        p.tgkill(pid, tid, SIGUSR1) == 0 && p.tgkill(pid, tid, SIGUSR2) == 0,
    );
    p.check(
        "rt_sigsuspend under SIGHUP alone releases both: EINTR",
        p.rt_sigsuspend(&support::one_set(SIGHUP), 8) == neg(EINTR),
    );
    p.check(
        "SIGUSR2's frame, built over SIGUSR1's, ran first and saved the temporary mask with \
         SIGUSR1's handler mask; SIGUSR1's, built first, saved the mask from before",
        support::count() == 2 && runs() == [(SIGUSR2, 0b101), (SIGUSR1, 0b111)],
    );
    p.rt_sigprocmask(SIG_SETMASK, Some(&before), None, 8);
    support::install_disposition(SIGUSR1, SIG_DFL);
    support::install_disposition(SIGUSR2, SIG_DFL);
}

pub const SCENARIO: Scenario = Scenario {
    name: "signal/raw_sigsuspend_frame_saved_mask",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_rt_sigprocmask,
        Syscall::N_rt_sigsuspend,
        Syscall::N_getpid,
        Syscall::N_gettid,
        Syscall::N_tgkill,
    ],
    trace: Some(TraceFacts {
        generations: &[
            Generation::thread(SIGUSR1),
            Generation::thread(SIGUSR1),
            Generation::thread(SIGUSR2),
        ],
        max_wakes_per_generation: None,
    }),
    ..DEFAULTS
};
