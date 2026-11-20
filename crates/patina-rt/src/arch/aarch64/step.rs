//! arm64's part of a spin probe (`spin.rs`).
//!
//! **One step.** There is no single-step bit a program may set: a step plants `brk #0x7061`
//! (through `/proc/self/mem`, which reaches read-only and execute-only text and makes the CPU
//! fetch the new word) at the instruction's successor, decoded with the frame's registers
//! (`proto::step`), and the SIGTRAP there (`TRAP_BRKPT`, `pc` at the `brk`) ends the step; the
//! original word goes back before anything else runs. A load-exclusive is stepped to the end of
//! its pair, never stopping inside it (a stop clears the exclusive monitor). A direct branch to
//! itself is taken in the frame. `svc`, `brk`, `udf`, undecoded branch forms and pairs the rule
//! does not cover are refused, and the probe gives up. A breakpoint is planted only in a
//! private executable mapping outside the runtime's region.
//!
//! BTI: `brk` is a valid target of every branch type, so a breakpoint at the target of an
//! indirect branch traps before any branch-target check; the frame keeps `PSTATE.BTYPE`, and
//! the restored instruction is checked as it would have been (measured on the dev VM: a `brk`
//! planted over a non-landing-pad instruction traps, and after restoring it the program's
//! own branch-target fault follows).
//!
//! **The state compared**: `x0`-`x30`, `sp`, `pc`, NZCV, `TPIDR_EL0` (not in the frame; the
//! runtime never changes it) and the frame's records (FPSIMD; SVE and the SME records where
//! the kernel writes them) but the fault syndrome.
//!
//! **Written memory.** arm64 has no soft-dirty bits (the kernel does not select
//! `HAVE_ARCH_SOFT_DIRTY`). Writes are found by userfaultfd's asynchronous write protection
//! (Linux 6.7) instead: when the probe starts, every writable mapping outside the runtime's
//! region is registered for write protection (`UFFD_USER_MODE_ONLY`: no privilege) and
//! protected; `PAGEMAP_SCAN` then reports the pages written since (`PAGE_IS_WRITTEN`). The
//! kernel resolves each write fault itself, so the program sees nothing. A page is protected
//! once per probe, not at every checkpoint, and the page an exclusive pair addresses is
//! unprotected before the pair is stepped: the fault of a store clears the exclusive monitor,
//! so a store-exclusive that faulted would fail, which a program reading its status (a weak
//! compare-and-swap) would see. (`RETRACES` covers a store that failed anyway.) The set written since the
//! start covers each iteration's, and every page in it is compared by contents. The descriptor
//! is closed when the probe ends, which unregisters and unprotects everything. Mappings that
//! are not writable cannot change without a system call, which ends the probe. A writable
//! mapping that cannot be registered (`MAP_DROPPABLE`) ends the probe without a find.

use super::Frame;
use crate::raw::*;
use crate::spin::{peek, peek_bytes, poke};
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering::Relaxed};
use proto::layout::*;
use proto::step::{Next, Regs, EXITS_MAX, PAIR_MAX};

const TRAP_BRKPT: i32 = 1;
const PSTATE_BTYPE: u64 = 3 << 10;
/// `PSTATE.nRW`: the thread runs AArch32 code.
const PSTATE_NRW: u64 = 1 << 4;

pub type Word = u32;
/// `brk #0x7061`.
pub const BRK: Word = 0xd420_0000 | 0x7061 << 5;

/// `regs_for_record`'s words and `TPIDR_EL0`.
pub const STATE_WORDS: usize = super::RECORD_WORDS + 1;

const STOPS: usize = EXITS_MAX + 1;

/// The breakpoints of the step in progress and the words they replaced.
#[repr(C)]
pub struct Stepper {
    at: [u64; STOPS],
    orig: [u32; STOPS],
    n: u8,
    /// The armed step runs an exclusive pair.
    pair: u8,
}

impl Stepper {
    pub const fn new() -> Stepper {
        Stepper {
            at: [0; STOPS],
            orig: [0; STOPS],
            n: 0,
            pair: 0,
        }
    }
}

/// What arming a step did.
pub enum Arm {
    /// Breakpoints are planted; the thread stops at one of them (or at the spin point).
    Armed,
    /// A branch to itself: the step was taken in the frame.
    Taken,
    /// The instruction cannot be stepped.
    Refused,
}

/// Arm one step of the thread at `frame`'s instruction; `point` is the spin point while its
/// breakpoint is planted (a stop there is the point's own trap), else 0.
pub fn step_arm(st: &mut Stepper, frame: &mut Frame, point: u64) -> Arm {
    st.n = 0;
    st.pair = 0;
    let pc = frame.pc;
    if frame.pstate & PSTATE_NRW != 0 {
        return Arm::Refused;
    }
    let Some(w) = peek(pc) else {
        return Arm::Refused;
    };
    let mut code = [0u32; PAIR_MAX];
    let mut k = 0;
    if proto::step::is_load_exclusive(w) {
        let mut bytes = [0u8; 4 * PAIR_MAX];
        k = peek_bytes(pc + 4, &mut bytes) / 4;
        for (i, c) in code[..k].iter_mut().enumerate() {
            let b = &bytes[4 * i..4 * i + 4];
            *c = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
    }
    let r = Regs {
        x: &frame.regs,
        pstate: frame.pstate,
    };
    let (stops, n) = match proto::step::next(pc, w, &r, &code[..k]) {
        Next::At(a) => ([a, 0, 0, 0, 0], 1),
        Next::Pair { at, n } => {
            st.pair = 1;
            // The pair's page loses its write protection now, not at the store: a protection
            // fault between the load and the store would fail the store, which a program that
            // reads the status (a weak compare-and-swap) would see. Unprotected, the page
            // counts as written and is compared by contents.
            let rn = (w >> 5 & 0x1f) as usize;
            unprotect(if rn == 31 { frame.sp } else { frame.regs[rn] });
            (at, n)
        }
        Next::SelfLoop { link } => {
            // A direct branch: no branch-target check follows it.
            if link {
                frame.regs[30] = pc + 4;
            }
            frame.pstate &= !PSTATE_BTYPE;
            return Arm::Taken;
        }
        Next::Refuse(_) => return Arm::Refused,
    };
    for &a in &stops[..n] {
        if a == point {
            continue;
        }
        let planted = plantable(a)
            && match peek(a) {
                Some(o) if poke(a, BRK) => {
                    st.at[st.n as usize] = a;
                    st.orig[st.n as usize] = o;
                    st.n += 1;
                    true
                }
                _ => false,
            };
        if !planted {
            step_disarm(st, frame);
            return Arm::Refused;
        }
    }
    Arm::Armed
}

/// A system call saves no flags in a register on arm64.
#[inline(always)]
pub fn syscall_flags(_frame: &mut Frame) {}

/// Whether a walk stops before the instruction at `pc`: an exclusive load (a pair stepped
/// could fail natively and retry, a different count by run).
pub fn stop_before(pc: u64) -> bool {
    crate::spin::peek(pc).is_some_and(proto::step::is_load_exclusive)
}

/// Take the step's breakpoints out (the step ended, or the probe did).
pub fn step_disarm(st: &mut Stepper, _frame: &mut Frame) {
    for i in (0..st.n as usize).rev() {
        poke(st.at[i], st.orig[i]);
    }
    st.n = 0;
}

/// Whether this SIGTRAP is at one of the step's breakpoints.
pub fn step_trap(st: &Stepper, code: i32, frame: &Frame) -> bool {
    code == TRAP_BRKPT && st.at[..st.n as usize].contains(&frame.pc)
}

/// A trap at one of the step's breakpoints is the stepper's, whatever else is going on.
#[inline(always)]
pub fn step_owned(_st: &Stepper) -> bool {
    true
}

/// Whether the step that just ended ran an exclusive pair.
#[inline(always)]
pub fn step_was_pair(st: &Stepper) -> bool {
    st.pair != 0
}

/// Whether this SIGTRAP is the planted breakpoint at `point` (`pc` is at it).
#[inline(always)]
pub fn at_point(code: i32, frame: &mut Frame, point: u64) -> bool {
    code == TRAP_BRKPT && frame.pc == point
}

/// Whether a breakpoint may be planted at `a` (`spin::plantable`), a word-aligned address.
pub fn plantable(a: u64) -> bool {
    a & 3 == 0 && crate::spin::plantable(a)
}

/// The state compared at a fixed point, and hashed in the yield's record.
pub fn state_words(frame: &Frame) -> [u64; STATE_WORDS] {
    let mut w = [0u64; STATE_WORDS];
    w[..super::RECORD_WORDS].copy_from_slice(&frame.regs_for_record());
    let tp: u64;
    unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nomem, nostack)) };
    w[super::RECORD_WORDS] = tp;
    w
}

/// The words of the yield record's arguments after the point and the period: `x0`, `sp` and
/// the flags.
pub fn record_args(g: &[u64; STATE_WORDS]) -> [u64; 3] {
    [g[0], g[31], g[33]]
}

const ESR_MAGIC: u32 = super::ESR_MAGIC;
const EXTRA_MAGIC: u32 = 0x4558_5401;

/// The records of `b` (from the frame's), as (magic, whole record), until the terminator.
fn records(b: &[u8]) -> impl Iterator<Item = (u32, &[u8])> {
    let mut off = 0usize;
    core::iter::from_fn(move || {
        let h = b.get(off..off + 8)?;
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if magic == 0 || size < 8 || off + size > b.len() {
            return None;
        }
        let r = &b[off..off + size];
        off += size;
        Some((magic, r))
    })
}

/// The frame's records up to their terminator. None: an `EXTRA` record (state beyond the
/// frame) or records that do not end inside it.
pub fn fp_state(frame: &Frame, max: usize) -> Option<&'static [u8]> {
    let b = &frame.records;
    let mut end = 0usize;
    for (magic, r) in records(b) {
        if magic == EXTRA_MAGIC {
            return None;
        }
        end += r.len();
    }
    if b.get(end..end + 8)? != [0u8; 8] || end > max {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(b.as_ptr(), end) })
}

/// Equal records, but the fault syndrome's.
pub fn fp_equal(a: &[u8], b: &[u8]) -> bool {
    let mut ra = records(a).filter(|r| r.0 != ESR_MAGIC);
    let mut rb = records(b).filter(|r| r.0 != ESR_MAGIC);
    loop {
        match (ra.next(), rb.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if x.1 == y.1 => {}
            _ => return false,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Written memory: userfaultfd's asynchronous write protection.

/// The probe's userfaultfd, from its first checkpoint to its end.
static UFFD: AtomicI32 = AtomicI32::new(-1);
/// The end of the highest program mapping when the probe registered them.
static TOP: AtomicU64 = AtomicU64::new(0);

/// Open what tracking needs (at the process's first probe): nothing (the descriptor is made
/// at each probe's start).
pub fn track_open(_open: impl Fn(&[u8], u64) -> i32) -> Option<i32> {
    UFFD.store(-1, Relaxed);
    Some(-1)
}

/// Times a probe may start its trace again where the path left the cycle it was about to
/// confirm or had found: a store-exclusive that failed once (above) makes a loop retry.
pub const RETRACES: u8 = 8;

/// At the probe's start: register and protect every writable program mapping.
pub fn track_begin(pagemap: i32) -> bool {
    track_end();
    register(pagemap)
}

/// At a checkpoint: nothing (the set written since the start is compared each time).
pub fn track_reset(_fd: i32, _pagemap: i32) -> bool {
    UFFD.load(Relaxed) >= 0
}

fn register(pagemap: i32) -> bool {
    const O_CLOEXEC: u64 = 0o2_000_000;
    const UFFD_USER_MODE_ONLY: u64 = 1;
    const UFFDIO_API: u64 = 0xc018_aa3f;
    const UFFDIO_REGISTER: u64 = 0xc020_aa00;
    const UFFD_API: u64 = 0xaa;
    const WP_HUGETLBFS_SHMEM: u64 = 1 << 12;
    const WP_UNPOPULATED: u64 = 1 << 13;
    const WP_ASYNC: u64 = 1 << 15;
    const MODE_WP: u64 = 2;
    const WRITABLE: u64 = 2;
    let fd = crate::fdlim::transient(|| unsafe {
        sc1(nr::USERFAULTFD, O_CLOEXEC | UFFD_USER_MODE_ONLY)
    });
    if fd < 0 {
        return false;
    }
    let h = crate::fdlim::place(fd, proto::layout::FD_PROBE_TRACK);
    if h < 0 {
        return false;
    }
    UFFD.store(h as i32, Relaxed);
    let want = WP_ASYNC | WP_UNPOPULATED | WP_HUGETLBFS_SHMEM;
    let mut api = [UFFD_API, want, 0u64];
    let r = unsafe { sc3(nr::IOCTL, h as u64, UFFDIO_API, api.as_mut_ptr() as u64) };
    if r != 0 || api[1] & want != want {
        track_end();
        return false;
    }
    let mut a = 0u64;
    let mut top = 0u64;
    while let Some(q) = crate::spin::vma(a, true) {
        a = q.vma_end;
        if q.vma_start >= RT_BASE && q.vma_end <= RT_REGION_END {
            continue;
        }
        top = q.vma_end;
        if q.vma_flags & WRITABLE == 0 {
            continue;
        }
        let mut reg = [q.vma_start, q.vma_end - q.vma_start, MODE_WP, 0u64];
        let r = unsafe {
            sc3(
                nr::IOCTL,
                h as u64,
                UFFDIO_REGISTER,
                reg.as_mut_ptr() as u64,
            )
        };
        if r != 0 {
            track_end();
            return false;
        }
    }
    TOP.store(top, Relaxed);
    // Protect everything: a scan that reports nothing.
    for (lo, hi) in ranges() {
        if !protect(pagemap, lo, hi) {
            track_end();
            return false;
        }
    }
    true
}

/// The program's part of the address space.
fn ranges() -> [(u64, u64); 2] {
    let top = TOP.load(Relaxed);
    [
        (0, RT_BASE.min(top)),
        (RT_REGION_END, top.max(RT_REGION_END)),
    ]
}

const PM_SCAN_WP_MATCHING: u64 = 1;
/// Pages of a mapping registered for asynchronous write protection.
const PAGE_IS_WPALLOWED: u64 = 1 << 0;
const PAGE_IS_WRITTEN: u64 = 1 << 1;

/// Write-protect the registered pages of `[lo, hi)`.
fn protect(pagemap: i32, lo: u64, hi: u64) -> bool {
    if lo >= hi {
        return true;
    }
    let mut a = crate::spin::ScanArg::new(lo, hi, PM_SCAN_WP_MATCHING, PAGE_IS_WRITTEN);
    let r = unsafe {
        sc3(
            nr::IOCTL,
            pagemap as u64,
            crate::spin::PAGEMAP_SCAN,
            &mut a as *mut crate::spin::ScanArg as u64,
        )
    };
    r == 0
}

/// Take the write protection off the page of `a` (the probe's tracking only; nothing when no
/// probe tracks).
fn unprotect(a: u64) {
    const UFFDIO_WRITEPROTECT: u64 = 0xc018_aa06;
    let fd = UFFD.load(Relaxed);
    if fd < 0 {
        return;
    }
    // struct uffdio_writeprotect { range { start, len }, mode }: mode 0 removes it.
    let mut wp = [a & !(PAGE - 1), PAGE, 0u64];
    unsafe {
        sc3(
            nr::IOCTL,
            fd as u64,
            UFFDIO_WRITEPROTECT,
            wp.as_mut_ptr() as u64,
        )
    };
}

/// The probe ended: closing the descriptor unregisters and unprotects every mapping.
pub fn track_end() {
    let fd = UFFD.swap(-1, Relaxed);
    if fd >= 0 {
        unsafe { sc1(nr::CLOSE, fd as u64) };
    }
}

/// Pages written since the probe started, outside the runtime's region, into `out`
/// (sorted). None when there are more than `out` holds.
pub fn track_written(pagemap: i32, out: &mut [u64]) -> Option<usize> {
    if UFFD.load(Relaxed) < 0 {
        return None;
    }
    let mut n = 0;
    for (lo, hi) in ranges() {
        // Only registered mappings: elsewhere every present page counts as written.
        n = crate::spin::scan(
            pagemap,
            lo,
            hi,
            PAGE_IS_WPALLOWED | PAGE_IS_WRITTEN,
            0,
            out,
            n,
        )?;
    }
    Some(n)
}
