//! x86_64's part of a spin probe (`spin.rs`): one step is the trap flag; the planted
//! breakpoint is the one-byte `int3`; the state compared is the general registers and the
//! XSAVE area; written memory is found by soft-dirty bits.

use super::reg::*;
use super::Frame;
use crate::raw::*;
use proto::layout::*;

const TF: u64 = 0x100;
const RF: u64 = 0x1_0000;
const SI_KERNEL: i32 = 0x80;
const TRAP_TRACE: i32 = 2;

/// The planted instruction and the unit `spin.rs` reads and writes code in.
pub type Word = u8;
pub const BRK: Word = 0xcc;

/// Words of the state compared at a fixed point.
pub const STATE_WORDS: usize = 18;

/// A step in progress: on x86_64, the trap flag in the frame holds it all.
#[repr(C)]
pub struct Stepper;

impl Stepper {
    pub const fn new() -> Stepper {
        Stepper
    }
}

/// What arming a step did.
pub enum Arm {
    /// The thread stops after one instruction (a trap the stepper recognises).
    Armed,
    /// The step was taken here, in the frame (arm64's branch to itself); never on x86_64.
    #[allow(dead_code)]
    Taken,
    /// The instruction cannot be stepped; never on x86_64.
    #[allow(dead_code)]
    Refused,
}

/// Arm one step of the thread at `frame`'s instruction.
#[inline(always)]
pub fn step_arm(_st: &mut Stepper, frame: &mut Frame, _point: u64) -> Arm {
    frame.gregs[EFL] |= TF;
    Arm::Armed
}

/// Disarm a step (taken or not).
#[inline(always)]
pub fn step_disarm(_st: &mut Stepper, frame: &mut Frame) {
    frame.gregs[EFL] &= !TF;
}

/// Whether this SIGTRAP (`si_code`) ended an armed step.
#[inline(always)]
pub fn step_trap(_st: &Stepper, code: i32, _frame: &Frame) -> bool {
    code == TRAP_TRACE
}

/// Whether a step trap that neither a probe nor a step over the point expected is still the
/// stepper's (arm64: its breakpoint); on x86_64 it is the program's own trap flag.
#[inline(always)]
pub fn step_owned(_st: &Stepper) -> bool {
    false
}

/// Whether the step that just ended was the first of an exclusive pair: none on x86_64.
#[inline(always)]
pub fn step_was_pair(_st: &Stepper) -> bool {
    false
}

/// Whether this SIGTRAP is the planted breakpoint at `point`; if so the frame is left at it.
#[inline(always)]
pub fn at_point(code: i32, frame: &mut Frame, point: u64) -> bool {
    if code == SI_KERNEL && frame.gregs[RIP].wrapping_sub(1) == point {
        frame.gregs[RIP] = point;
        return true;
    }
    false
}

/// Whether a breakpoint may be planted at `a` (`spin::plantable`).
#[inline(always)]
pub fn plantable(a: u64) -> bool {
    crate::spin::plantable(a)
}

/// The state compared at a fixed point, and hashed in the yield's record: the general
/// registers, without the trap and resume flags.
pub fn state_words(frame: &Frame) -> [u64; STATE_WORDS] {
    let mut r = [0u64; STATE_WORDS];
    r.copy_from_slice(&frame.gregs[..18]);
    r[EFL] &= !(TF | RF);
    r
}

/// The words of the yield record's arguments after the point and the period.
pub fn record_args(g: &[u64; STATE_WORDS]) -> [u64; 3] {
    [g[RCX], g[RSP], g[EFL]]
}

/// The FPU/SIMD state of the frame (the XSAVE area). None: a form not understood.
pub fn fp_state(frame: &Frame, max: usize) -> Option<&'static [u8]> {
    if frame.fpstate == 0 {
        return Some(&[]);
    }
    let base = frame.fpstate as *const u8;
    let magic = unsafe { core::ptr::read_unaligned(base.add(464) as *const u32) };
    let len = if magic == 0x4650_5853 {
        unsafe { core::ptr::read_unaligned(base.add(480) as *const u32) as usize }
    } else {
        512
    };
    if !(512..=max).contains(&len) {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(base, len) })
}

/// Equal FPU/SIMD states, without the kernel's software bytes (464..512).
pub fn fp_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a[..464] == b[..464] && a[512..] == b[512..]
}

// ---------------------------------------------------------------------------------------
// Written memory: soft-dirty bits.

/// The highest user address.
const USER_TOP: u64 = 0x7fff_ffff_f000;

/// Open what tracking needs (at the process's first probe): `/proc/self/clear_refs`.
pub fn track_open(open: impl Fn(&[u8], u64) -> i32) -> Option<i32> {
    let fd = open(b"/proc/self/clear_refs\0", 1);
    (fd >= 0).then_some(fd)
}

/// Times a probe may start its trace again where the path left its cycle: none (a probe
/// gives up).
pub const RETRACES: u8 = 0;

/// At the probe's start: nothing (the first checkpoint clears the bits).
#[inline(always)]
pub fn track_begin(_pagemap: i32) -> bool {
    true
}

/// Start counting writes from now (every checkpoint).
pub fn track_reset(fd: i32, _pagemap: i32) -> bool {
    let b = b"4";
    unsafe { sc3(nr::WRITE, fd as u64, b.as_ptr() as u64, 1) == 1 }
}

/// The probe ended: nothing to undo.
#[inline(always)]
pub fn track_end() {}

/// Pages written since the last reset, outside the runtime's region, into `out` (sorted).
/// None when there are more than `out` holds.
pub fn track_written(pagemap: i32, out: &mut [u64]) -> Option<usize> {
    const PAGE_IS_SOFT_DIRTY: u64 = 1 << 7;
    let mut n = 0;
    for (lo, hi) in [(0, RT_BASE), (RT_REGION_END, USER_TOP)] {
        n = crate::spin::scan(pagemap, lo, hi, PAGE_IS_SOFT_DIRTY, 0, out, n)?;
    }
    Some(n)
}
