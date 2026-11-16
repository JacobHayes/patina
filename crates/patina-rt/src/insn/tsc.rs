//! `rdtsc`/`rdtscp`: `PR_SET_TSC(PR_TSC_SIGSEGV)` makes both raise a #GP (SIGSEGV, `SI_KERNEL`,
//! no fault address). The bytes at the saved instruction pointer say which one it was. The value
//! is the virtual clock scaled by a fixed nominal frequency (3 GHz); `rdtscp`'s auxiliary value
//! (the kernel's CPU number in `TSC_AUX`) is 0. Each emulation is a boundary event charged like a
//! trap; no supervisor round trip unless the usual preemption draw fires.

use crate::entry::{charge, maybe_yield};
use crate::state::{ctl, thread};
use crate::sys::sig::{self, SigInfo};
use crate::trap::{reg::*, TrapFrame};
use core::sync::atomic::Ordering::Relaxed;
use proto::ctl::{INSN_RDTSC, INSN_RDTSCP};

const SI_KERNEL: i32 = 0x80;

/// Nominal timestamp-counter frequency: ticks per virtual nanosecond.
pub const TSC_PER_NS: u64 = 3;

/// Boundary-record codes (`Rec::nr` of an `insn` record).
pub const CODE_RDTSC: u32 = 0x0f31;
pub const CODE_RDTSCP: u32 = 0x0f01f9;

/// The guest's own `PR_SET_TSC` mode (1 = enabled, 2 = SIGSEGV), per process: the real mode
/// is always SIGSEGV. A guest that asked for SIGSEGV gets the fault, not a value.
static VMODE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

pub fn virtual_mode() -> u32 {
    VMODE.load(Relaxed)
}

pub fn set_virtual_mode(m: u64) -> bool {
    if m != 1 && m != 2 {
        return false;
    }
    VMODE.store(m as u32, Relaxed);
    true
}

pub fn try_emulate(frame: &mut TrapFrame, sig: i32, info: &SigInfo) -> bool {
    if VMODE.load(Relaxed) == 2 {
        return false;
    }
    let rip = frame.gregs[RIP];
    if sig as u64 != sig::SIGSEGV || (info[1] & 0xffff_ffff) as i32 != SI_KERNEL {
        return false;
    }
    let b = unsafe { core::slice::from_raw_parts(rip as *const u8, 3) };
    let len = if b[0] == 0x0f && b[1] == 0x31 {
        2
    } else if b[0] == 0x0f && b[1] == 0x01 && b[2] == 0xf9 {
        3
    } else {
        return false;
    };
    let ts = thread();
    charge(ts);
    let c = ctl();
    crate::insn::bump(&c.stats.insn_emulations, 1);
    crate::insn::count_emulated(if len == 2 { INSN_RDTSC } else { INSN_RDTSCP });
    let tsc = c.vclock_ns.load(Relaxed).wrapping_mul(TSC_PER_NS);
    frame.gregs[RAX] = tsc & 0xffff_ffff;
    frame.gregs[RDX] = tsc >> 32;
    if len == 3 {
        frame.gregs[RCX] = 0;
    }
    frame.gregs[RIP] = rip + len;
    crate::log::insn(if len == 2 { CODE_RDTSC } else { CODE_RDTSCP }, rip, tsc);
    maybe_yield(ts);
    true
}

/// At runtime start: make sure the counter faults (the setting survives fork and execve, but
/// a process could have been started without it). Returns whether it had to be set.
pub fn ensure_faulting() -> bool {
    use crate::raw::*;
    const PR_GET_TSC: u64 = 25;
    const PR_SET_TSC: u64 = 26;
    const PR_TSC_SIGSEGV: u64 = 2;
    let mut cur: u32 = 0;
    let got = unsafe { sc2(nr::PRCTL, PR_GET_TSC, &mut cur as *mut u32 as u64) };
    if got == 0 && cur as u64 == PR_TSC_SIGSEGV {
        return false;
    }
    if unsafe { sc2(nr::PRCTL, PR_SET_TSC, PR_TSC_SIGSEGV) } != 0 {
        crate::fatal(b"PR_SET_TSC");
    }
    true
}
