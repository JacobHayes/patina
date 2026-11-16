//! The request protocol: the only way the turn moves.

use crate::raw::*;
use crate::state::{ctl, thread};
use core::sync::atomic::Ordering::*;
use proto::ctl::{Op, Reply, Request};

unsafe fn post(op: Op, args: [u64; 6]) -> *mut proto::Slot {
    let ts = thread();
    let c = ctl();
    let slot = c.slot(ts.slot as usize);
    core::ptr::write_volatile(
        &mut (*slot).req,
        Request {
            op: op as u32,
            _pad: 0,
            args,
        },
    );
    (*slot).go.store(0, SeqCst);
    c.pending_slot.store(ts.slot, SeqCst);
    c.sup_word.store(1, SeqCst);
    futex_wake(&c.sup_word as *const _ as *const u32, 1);
    slot
}

/// Give the turn to the supervisor with a request; return when it gives the turn back.
/// Every request (in particular every park) first checks for real signals from outside.
pub fn call_sup(op: Op, args: [u64; 6]) -> Reply {
    outside_check();
    call_sup_raw(op, args)
}

/// Real signals pending for this task other than SIGCHLD: every asynchronous signal is held
/// blocked in the kernel, so anything pending was sent from outside the sandbox.
/// The call is made from runtime text and does not trap.
pub fn outside_check() {
    const SIGCHLD_BIT: u64 = 1 << (17 - 1);
    let mut set: u64 = 0;
    let r = unsafe { sc2(nr::RT_SIGPENDING, &mut set as *mut u64 as u64, 8) };
    let set = set & !SIGCHLD_BIT;
    if r == 0 && set != 0 {
        let sig = set.trailing_zeros() as u64 + 1;
        host_error(sig as i64, 0, proto::ctl::HE_OUTSIDE_SIGNAL);
    }
}

fn call_sup_raw(op: Op, args: [u64; 6]) -> Reply {
    unsafe {
        let slot = post(op, args);
        while (*slot).go.load(Acquire) == 0 {
            futex_wait(&(*slot).go as *const _ as *const u32, 0);
        }
        core::ptr::read_volatile(&(*slot).rep)
    }
}

/// Send a request the supervisor never answers (exit); the caller exits right after.
pub fn call_sup_noreply(op: Op, args: [u64; 6]) {
    unsafe {
        post(op, args);
    }
}

/// End the run as `unsupported`, naming the call. Never returns: the supervisor kills the sandbox.
pub fn stop(nr: u64, a0: u64) -> ! {
    ctl().stop_nr.store(nr, Relaxed);
    call_sup_raw(Op::Stop, [nr, a0, 0, 0, 0, 0]);
    hang()
}

/// End the run as `infra`.
pub fn host_error(errno: i64, nr: u64, code: u64) -> ! {
    call_sup_raw(Op::HostError, [errno as u64, nr, code, 0, 0, 0]);
    hang()
}

pub fn hang() -> ! {
    loop {
        unsafe {
            sc1(nr::EXIT_GROUP, 125);
        }
    }
}
