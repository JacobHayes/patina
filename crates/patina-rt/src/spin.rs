//! Spin probes: find a syscall-free spin-wait and make it a scheduling point, without
//! privilege and without changing the schedule's dependence on the seed.
//!
//! The supervisor runs one guest thread at a time, so a thread that waits for another by
//! spinning on memory, with no system call and no `pause` in its loop, never hands over.
//! When the thread holding the turn has computed for a while with no boundary event, the
//! supervisor sends it a probe (a real `SIGTRAP` by `tgkill`; nothing else sends one). The
//! probe arrives at an arbitrary instruction, which is not deterministic. What the probe
//! looks for is:
//!
//! 1. **A periodic path.** Single steps from the arrival point record instruction
//!    addresses until they repeat with a period `P` (the first return to the start whose
//!    next `P` addresses equal the first `P`).
//! 2. **A canonical point.** The least rotation of the `P` addresses names one position in
//!    the cycle, the same whichever instruction the probe arrived at.
//! 3. **A fixed point.** At that position, a full iteration later and another after that,
//!    the registers (general, flags, the whole FPU/SIMD state) are equal, and so is every
//!    page the iteration wrote (soft-dirty bits: `/proc/self/clear_refs`, `PAGEMAP_SCAN`;
//!    the runtime's own region is excluded). The thread's next state is a function of its
//!    state alone (no other thread runs, no system call is made), so equal states mean the
//!    loop never ends by itself, and every later arrival at the point is in that same state.
//!
//! The state there is therefore the same in every run, however late the probe came: the
//! thread yields there exactly as at a trap (a `preempt` record with `nr` 2, virtual time
//! charged, virtual signals delivered at its exit). It then stays a scheduling point: an
//! `int3` is planted at it, and each arrival yields again, until the thread's next other
//! runtime entry. A probe that does not find a fixed point changes nothing the guest can see,
//! so the supervisor can probe again, and in the end reports `compute-stall`.
//!
//! Not found: loops whose iterations change state (a counter in memory or a register), loops
//! longer than the trace, and code the runtime cannot single-step. Hazards as for hops (see
//! `pmu.rs`): a guest that reads its own flags sees the trap flag, and one that reads its own
//! code at the point sees the planted byte.

use crate::raw::*;
use crate::state::{config, ctl, thread, ThreadState};
use crate::sys::sig::SigInfo;
use crate::trap::{reg::*, TrapFrame};
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering::Relaxed};
use proto::ctl::{Op, SCHED_SPIN_PROBE};
use proto::layout::*;

const PH_NONE: u64 = 0;
const PH_TRACE: u64 = 1;
const PH_ALIGN: u64 = 2;
const PH_CHECK: u64 = 3;

const TF: u64 = 0x100;
const RF: u64 = 0x1_0000;
const SI_TKILL: i32 = -6;
const SI_KERNEL: i32 = 0x80;
const TRAP_TRACE: i32 = 2;

/// Trace length (single steps) a probe may take to find the period.
const TRACE_MAX: usize = 1 << 16;
/// Pages an iteration may write.
const COPY_PAGES: usize = 256;
/// Iterations compared before a probe gives up.
const CHECKS: u64 = 4;
const FP_MAX: usize = 8192;
const REGIONS: usize = 128;

// Per-process scratch at the top of the runtime's private region, mapped on first use: the
// trace, the saved state of the last checkpoint and its pages.
const TRACE_OFF: u64 = 0;
const FP_OFF: u64 = TRACE_OFF + (TRACE_MAX as u64) * 8;
const PAGES_LIST_OFF: u64 = FP_OFF + FP_MAX as u64;
const COPY_OFF: u64 = PAGES_LIST_OFF + (COPY_PAGES as u64) * 8;
const SCRATCH_SIZE: u64 = (COPY_OFF + (COPY_PAGES as u64) * PAGE + 0xfffff) & !0xfffff;
const SCRATCH: u64 = RT_PRIV + RT_PRIV_SIZE - SCRATCH_SIZE;

/// Per-thread probe state, in `ThreadState`.
#[repr(C)]
pub struct Spin {
    pub phase: u64,
    /// Steps taken (index into the trace), the candidate period, the period found, the step
    /// index of the canonical position, checkpoints taken.
    pub i: u64,
    pub cand: u64,
    pub period: u64,
    pub target: u64,
    pub checks: u64,
    /// The last checkpoint's registers (r8..rip, flags) and how many pages it saved.
    pub regs: [u64; 18],
    pub npages: u64,
    pub fp_len: u64,
    /// The spin point (0: none), its original byte, whether `int3` is planted there, and
    /// whether the thread is stepping over it.
    pub point: u64,
    pub orig: u8,
    pub planted: u8,
    pub over: u8,
    pub _pad: [u8; 5],
}

impl Spin {
    pub const fn new() -> Spin {
        Spin {
            phase: PH_NONE,
            i: 0,
            cand: 0,
            period: 0,
            target: 0,
            checks: 0,
            regs: [0; 18],
            npages: 0,
            fp_len: 0,
            point: 0,
            orig: 0,
            planted: 0,
            over: 0,
            _pad: [0; 5],
        }
    }
}

fn bump(a: &AtomicU64, n: u64) {
    a.store(a.load(Relaxed) + n, Relaxed);
}

fn in_runtime(a: u64) -> bool {
    (RT_BASE..RT_REGION_END).contains(&a)
}

// ---------------------------------------------------------------------------------------
// Process resources: the scratch mapping and `/proc/self` descriptors, opened lazily and
// reopened in a fork child (a descriptor on `/proc/self/...` names the process that opened it).

static OWNER: AtomicI32 = AtomicI32::new(0);
static MEM: AtomicI32 = AtomicI32::new(-1);
static PAGEMAP: AtomicI32 = AtomicI32::new(-1);
static CLEAR: AtomicI32 = AtomicI32::new(-1);

fn open_hidden(path: &[u8], flags: u64) -> i32 {
    const F_DUPFD_CLOEXEC: u64 = 1030;
    let fd = unsafe {
        sc4(
            nr::OPENAT,
            (-100i64) as u64,
            path.as_ptr() as u64,
            flags | 0x80000,
            0,
        )
    };
    if fd < 0 {
        return -1;
    }
    let h = unsafe { sc3(nr::FCNTL, fd as u64, F_DUPFD_CLOEXEC, FD_RT_DYN as u64) };
    unsafe { sc1(nr::CLOSE, fd as u64) };
    h as i32
}

/// Make the scratch and descriptors ready for this process. False if they cannot be.
fn resources() -> bool {
    let pid = unsafe { sc0(nr::GETPID) } as i32;
    if OWNER.load(Relaxed) == pid {
        return true;
    }
    for d in [&MEM, &PAGEMAP, &CLEAR] {
        let fd = d.swap(-1, Relaxed);
        if fd >= 0 {
            unsafe { sc1(nr::CLOSE, fd as u64) };
        }
    }
    // A fork child inherits the parent's mapping; a fresh image maps it.
    let r = unsafe {
        sc6(
            nr::MMAP,
            SCRATCH,
            SCRATCH_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            u64::MAX,
            0,
        )
    };
    if r as u64 != SCRATCH && r != -e::EEXIST {
        return false;
    }
    let mem = open_hidden(b"/proc/self/mem\0", 2);
    let pm = open_hidden(b"/proc/self/pagemap\0", 0);
    let cl = open_hidden(b"/proc/self/clear_refs\0", 1);
    MEM.store(mem, Relaxed);
    PAGEMAP.store(pm, Relaxed);
    CLEAR.store(cl, Relaxed);
    if mem < 0 || pm < 0 || cl < 0 {
        return false;
    }
    OWNER.store(pid, Relaxed);
    true
}

fn trace() -> &'static mut [u64] {
    unsafe { core::slice::from_raw_parts_mut((SCRATCH + TRACE_OFF) as *mut u64, TRACE_MAX) }
}

fn poke(a: u64, b: u8) -> bool {
    let r = unsafe {
        sc4(
            nr::PWRITE64,
            MEM.load(Relaxed) as u64,
            &b as *const u8 as u64,
            1,
            a,
        )
    };
    r == 1
}

fn peek(a: u64) -> Option<u8> {
    let mut b = 0u8;
    let r = unsafe {
        sc4(
            nr::PREAD64,
            MEM.load(Relaxed) as u64,
            &mut b as *mut u8 as u64,
            1,
            a,
        )
    };
    (r == 1).then_some(b)
}

fn clear_soft_dirty() -> bool {
    let b = b"4";
    unsafe { sc3(nr::WRITE, CLEAR.load(Relaxed) as u64, b.as_ptr() as u64, 1) == 1 }
}

#[repr(C)]
struct ScanArg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

/// Pages written since the last clear, outside the runtime's region, into `out` (sorted).
/// None when there are more than `out` holds.
fn dirty_pages(out: &mut [u64]) -> Option<usize> {
    const PAGEMAP_SCAN: u64 = 0xc060_6610;
    const PAGE_IS_SOFT_DIRTY: u64 = 1 << 7;
    let mut n = 0;
    for (lo, hi) in [(0, RT_BASE), (RT_REGION_END, 0x7fff_ffff_f000)] {
        let mut start = lo;
        while start < hi {
            let mut regions = [[0u64; 3]; REGIONS];
            let mut a = ScanArg {
                size: core::mem::size_of::<ScanArg>() as u64,
                flags: 0,
                start,
                end: hi,
                walk_end: 0,
                vec: regions.as_mut_ptr() as u64,
                vec_len: REGIONS as u64,
                max_pages: 0,
                category_inverted: 0,
                category_mask: PAGE_IS_SOFT_DIRTY,
                category_anyof_mask: 0,
                return_mask: PAGE_IS_SOFT_DIRTY,
            };
            let r = unsafe {
                sc3(
                    nr::IOCTL,
                    PAGEMAP.load(Relaxed) as u64,
                    PAGEMAP_SCAN,
                    &mut a as *mut ScanArg as u64,
                )
            };
            if r < 0 {
                return None;
            }
            for reg in &regions[..r as usize] {
                let mut p = reg[0];
                while p < reg[1] {
                    if n == out.len() {
                        return None;
                    }
                    out[n] = p;
                    n += 1;
                    p += PAGE;
                }
            }
            if (r as usize) < REGIONS || a.walk_end <= start {
                break;
            }
            start = a.walk_end;
        }
    }
    Some(n)
}

// ---------------------------------------------------------------------------------------
// Entry points.

/// A runtime entry other than the spin point (`on_sigsys`, `on_fault`): a probe in progress
/// ends without a trace, and the spin point stops being one.
#[inline]
pub fn enter(ts: &mut ThreadState, frame: Option<&mut TrapFrame>) {
    let s = &ts.spin;
    if s.phase == PH_NONE && s.point == 0 && s.over == 0 {
        return;
    }
    enter_slow(ts, frame);
}

#[inline(never)]
fn enter_slow(ts: &mut ThreadState, frame: Option<&mut TrapFrame>) {
    if let Some(f) = frame {
        if ts.spin.phase != PH_NONE || ts.spin.over != 0 {
            f.gregs[EFL] &= !TF;
        }
    }
    ts.spin.phase = PH_NONE;
    disarm(ts);
}

fn disarm(ts: &mut ThreadState) {
    let s = &mut ts.spin;
    if s.planted != 0 {
        poke(s.point, s.orig);
        s.planted = 0;
    }
    s.over = 0;
    s.point = 0;
}

/// Every SIGTRAP first: probes, single steps and the spin point. True when handled.
pub fn on_sigtrap(info: &SigInfo, frame: &mut TrapFrame) -> bool {
    let ts = thread();
    let code = (info[1] & 0xffff_ffff) as i32;
    let rip = frame.gregs[RIP];
    if code == SI_TKILL && (info[2] & 0xffff_ffff) as i32 == 1 {
        // A probe from the supervisor (PID 1). Ignored unless the thread is in guest code
        // with nothing of ours in progress.
        if config().sched & SCHED_SPIN_PROBE != 0
            && !in_runtime(rip)
            && ts.vfork == 0
            && ts.spin.phase == PH_NONE
            && ts.spin.over == 0
        {
            start(ts, frame);
        }
        return true;
    }
    if in_runtime(rip) {
        return false;
    }
    if code == SI_KERNEL && ts.spin.planted != 0 && rip.wrapping_sub(1) == ts.spin.point {
        if ts.spin.phase != PH_NONE {
            ts.spin.phase = PH_NONE;
        }
        frame.gregs[EFL] &= !TF;
        let s = &mut ts.spin;
        poke(s.point, s.orig);
        s.planted = 0;
        frame.gregs[RIP] = s.point;
        bump(&ctl().sched.spin_yields, 1);
        spin_yield(ts, frame, 0);
        return true;
    }
    if code == TRAP_TRACE {
        if ts.spin.over != 0 {
            // Stepped over the spin point: plant it again.
            frame.gregs[EFL] &= !TF;
            let s = &mut ts.spin;
            s.over = 0;
            if s.point != 0 && poke(s.point, 0xcc) {
                s.planted = 1;
            } else {
                s.point = 0;
            }
            return true;
        }
        if ts.spin.phase != PH_NONE {
            step(ts, frame);
            return true;
        }
    }
    false
}

fn abort(ts: &mut ThreadState, frame: &mut TrapFrame) {
    ts.spin.phase = PH_NONE;
    frame.gregs[EFL] &= !TF;
}

fn start(ts: &mut ThreadState, frame: &mut TrapFrame) {
    let c = ctl();
    bump(&c.sched.spin_probes, 1);
    if !resources() {
        return;
    }
    let s = &mut ts.spin;
    trace()[0] = frame.gregs[RIP];
    s.i = 0;
    s.cand = 0;
    s.period = 0;
    s.checks = 0;
    s.npages = 0;
    s.phase = PH_TRACE;
    frame.gregs[EFL] |= TF;
}

/// Index of the least rotation of `s` (the two-pointer minimum-expression algorithm).
fn least_rotation(s: &[u64]) -> usize {
    let n = s.len();
    let (mut i, mut j, mut k) = (0usize, 1usize, 0usize);
    while i < n && j < n && k < n {
        let (a, b) = (s[(i + k) % n], s[(j + k) % n]);
        if a == b {
            k += 1;
            continue;
        }
        if a > b {
            i += k + 1;
        } else {
            j += k + 1;
        }
        if i == j {
            j += 1;
        }
        k = 0;
    }
    i.min(j)
}

/// A single step of a probe finished.
fn step(ts: &mut ThreadState, frame: &mut TrapFrame) {
    frame.gregs[EFL] &= !TF;
    bump(&ctl().sched.spin_steps, 1);
    let rip = frame.gregs[RIP];
    let t = trace();
    let s = &mut ts.spin;
    s.i += 1;
    let i = s.i as usize;
    match s.phase {
        PH_TRACE => {
            if i >= TRACE_MAX {
                return abort(ts, frame);
            }
            t[i] = rip;
            let cand = s.cand as usize;
            if cand == 0 {
                if rip == t[0] {
                    s.cand = i as u64;
                }
            } else if rip != t[i - cand] {
                s.cand = if rip == t[0] { i as u64 } else { 0 };
            } else if i == 2 * cand {
                let p = cand;
                s.period = p as u64;
                s.target = (2 * p + least_rotation(&t[..p])) as u64;
                s.phase = PH_ALIGN;
                if i as u64 == s.target {
                    s.phase = PH_CHECK;
                    if !checkpoint(ts, frame) {
                        return;
                    }
                }
            }
        }
        _ => {
            let p = s.period as usize;
            if rip != t[i % p] {
                return abort(ts, frame);
            }
            let at_check = if s.phase == PH_ALIGN {
                i as u64 == s.target
            } else {
                (i as u64 - s.target).is_multiple_of(p as u64)
            };
            if at_check {
                s.phase = PH_CHECK;
                if !checkpoint(ts, frame) {
                    return;
                }
            }
        }
    }
    if ts.spin.phase != PH_NONE {
        frame.gregs[EFL] |= TF;
    }
}

fn regs_of(frame: &TrapFrame) -> [u64; 18] {
    let mut r = [0u64; 18];
    r.copy_from_slice(&frame.gregs[..18]);
    r[EFL] &= !(TF | RF);
    r
}

/// The FPU/SIMD state of the frame, without the kernel's software bytes (464..512).
fn fp_of(frame: &TrapFrame) -> Option<&'static [u8]> {
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
    if !(512..=FP_MAX).contains(&len) {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(base, len) })
}

fn fp_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a[..464] == b[..464] && a[512..] == b[512..]
}

/// The thread is at the canonical position. Compare with the last checkpoint; on a fixed
/// point, yield. Returns false when the probe ended (found or given up).
fn checkpoint(ts: &mut ThreadState, frame: &mut TrapFrame) -> bool {
    let list = unsafe {
        core::slice::from_raw_parts_mut((SCRATCH + PAGES_LIST_OFF) as *mut u64, COPY_PAGES)
    };
    let saved_fp =
        unsafe { core::slice::from_raw_parts_mut((SCRATCH + FP_OFF) as *mut u8, FP_MAX) };
    let copies = SCRATCH + COPY_OFF;
    let regs = regs_of(frame);
    let Some(fp) = fp_of(frame) else {
        abort(ts, frame);
        return false;
    };
    let s = &mut ts.spin;
    if s.checks > 0 {
        let mut now = [0u64; COPY_PAGES];
        let Some(n) = dirty_pages(&mut now) else {
            abort(ts, frame);
            return false;
        };
        let prev = &list[..s.npages as usize];
        let mut equal =
            s.checks > 1 && regs == s.regs && fp_equal(fp, &saved_fp[..s.fp_len as usize]);
        // Every page written in this iteration was written in the last one too (so its
        // contents then were saved) and holds the same bytes.
        let mut k = 0;
        for &p in &now[..n] {
            if !equal {
                break;
            }
            while k < prev.len() && prev[k] < p {
                k += 1;
            }
            equal = k < prev.len()
                && prev[k] == p
                && unsafe {
                    core::slice::from_raw_parts(p as *const u8, PAGE as usize)
                        == core::slice::from_raw_parts(
                            (copies + k as u64 * PAGE) as *const u8,
                            PAGE as usize,
                        )
                };
        }
        if equal {
            found(ts, frame);
            return false;
        }
        if s.checks > CHECKS {
            abort(ts, frame);
            return false;
        }
        // Save this iteration's pages for the next comparison.
        list[..n].copy_from_slice(&now[..n]);
        for (j, &p) in now[..n].iter().enumerate() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    p as *const u8,
                    (copies + j as u64 * PAGE) as *mut u8,
                    PAGE as usize,
                )
            };
        }
        s.npages = n as u64;
    }
    s.regs = regs;
    saved_fp[..fp.len()].copy_from_slice(fp);
    s.fp_len = fp.len() as u64;
    s.checks += 1;
    if !clear_soft_dirty() {
        abort(ts, frame);
        return false;
    }
    true
}

/// A fixed point: the canonical position is a spin point from now on.
fn found(ts: &mut ThreadState, frame: &mut TrapFrame) {
    let c = ctl();
    bump(&c.sched.spin_found, 1);
    bump(&c.sched.spin_yields, 1);
    ts.spin.phase = PH_NONE;
    frame.gregs[EFL] &= !TF;
    let period = ts.spin.period;
    spin_yield(ts, frame, period);
}

/// Yield at the spin point (the frame's `rip`), as at a trap; then keep it a spin point.
fn spin_yield(ts: &mut ThreadState, frame: &mut TrapFrame, period: u64) {
    let c = ctl();
    let point = frame.gregs[RIP];
    // A spin point is a runtime entry at a state that is the same in every run (it was found
    // as a fixed point, or arrived at again): charge compute events here, as at a trap.
    crate::compute::enter(ts);
    ts.seq = c.seq.load(Relaxed) + 1;
    c.seq.store(ts.seq, Relaxed);
    let t = c.vclock_ns.load(Relaxed) + c.config.spin_charge_ns;
    c.vclock_ns.store(t, Relaxed);
    let g = regs_of(frame);
    let bytes = unsafe { core::slice::from_raw_parts(g.as_ptr() as *const u8, 18 * 8) };
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns: t,
        slot: ts.slot as u16,
        kind: proto::RecKind::Preempt as u8,
        class: 0,
        nr: 2,
        args: [point, period, g[RCX], g[RSP], g[EFL], 0],
        ret: 0,
        out_hash: proto::rec::hash_bytes(0, bytes),
        in_hash: 0,
    };
    crate::log::append(&rec);
    crate::sup::call_sup(Op::Yield, [0; 6]);
    crate::sys::sig::trap_exit(frame, None);
    crate::entry::check_real_mask(frame);
    crate::compute::exit(ts);
    // Arm the point: plant `int3` there, or, when the thread resumes at it, step its
    // instruction first and plant after.
    let Some(orig) = peek(point) else {
        return;
    };
    let s = &mut ts.spin;
    s.point = point;
    s.orig = orig;
    if frame.gregs[RIP] == point {
        s.over = 1;
        frame.gregs[EFL] |= TF;
    } else if poke(point, 0xcc) {
        s.planted = 1;
    } else {
        s.point = 0;
    }
}
