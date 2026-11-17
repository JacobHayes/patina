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
//!    page the iteration wrote (x86_64: soft-dirty bits; arm64: userfaultfd's asynchronous
//!    write-protection; both read by `PAGEMAP_SCAN`; the runtime's own region is excluded).
//!    The thread's next state is a function of its
//!    state alone (no other thread runs, no system call is made), so equal states mean the
//!    loop never ends by itself, and every later arrival at the point is in that same state.
//!
//! The state there is therefore the same in every run, however late the probe came: the
//! thread yields there exactly as at a trap (a `preempt` record with `nr` 2, virtual time
//! charged, virtual signals delivered at its exit). It then stays a scheduling point: a
//! breakpoint is planted at it, and each arrival yields again, until the thread's next other
//! runtime entry. A probe that does not find a fixed point changes nothing the guest can see,
//! so the supervisor can probe again, and in the end reports `compute-stall`.
//!
//! The architecture's part is `arch::step`: how one step is taken and recognised (x86_64: the
//! trap flag; arm64: a `brk` planted at the decoded successor, `proto::step`), the planted
//! word (`int3`, `brk`), the state words, and how written pages are tracked. Only one guest
//! thread runs at a time, and every planted word is restored before the thread yields or
//! enters the runtime otherwise, so no other thread or process executes one; a fork child
//! gets copies of the pages as they were before the plant.
//!
//! Not found: loops whose iterations change state (a counter in memory or a register), loops
//! longer than the trace, and code the runtime cannot step (arm64: an exclusive pair the
//! rule does not cover, an exception-generating instruction, an undecoded branch, code in a
//! writable mapping; a wait inside a pair, `ldaxr` and a branch back to it while the value is
//! held, never ends its step, so its probe never ends either and the run ends
//! `compute-stall`). A store-exclusive also fails, natively, when the host interrupts its
//! pair; a program that reads the status (a weak compare-and-swap) can take another path,
//! more or less often by host, which Patina does not hide. Hazards
//! as for hops (see `pmu.rs`): a guest that reads its own flags sees the trap flag (x86_64),
//! and one that reads its own code at the point or at the step's stop while it is planted
//! sees the breakpoint (only the stepped thread runs then, and it reads its code only by
//! executing a load; a guest that checksums its text between probes sees it unchanged,
//! `spinpoints text`).

use crate::arch::step::{self as st, Arm, Word, STATE_WORDS};
use crate::arch::Frame;
use crate::raw::*;
use crate::state::{config, ctl, thread, ThreadState};
use crate::sys::sig::SigInfo;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering::Relaxed};
use proto::ctl::{Op, SCHED_SPIN_PROBE};
use proto::layout::*;

const PH_NONE: u64 = 0;
const PH_TRACE: u64 = 1;
const PH_ALIGN: u64 = 2;
const PH_CHECK: u64 = 3;

const SI_TKILL: i32 = -6;

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
    /// The last checkpoint's registers (`arch::step::state_words`) and how many pages it
    /// saved.
    pub regs: [u64; STATE_WORDS],
    pub npages: u64,
    pub fp_len: u64,
    /// The spin point (0: none), its original word, whether the breakpoint is planted there,
    /// and whether the thread is stepping over it.
    pub point: u64,
    pub orig: Word,
    pub planted: u8,
    pub over: u8,
    /// Whether the trace was restarted after the probe's first exclusive pair; restarts left
    /// where the path leaves its cycle (from `arch::step::RETRACES`).
    pub anchored: u8,
    pub retraces: u8,
    /// The step in progress (`arch::step`).
    pub st: st::Stepper,
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
            regs: [0; STATE_WORDS],
            npages: 0,
            fp_len: 0,
            point: 0,
            orig: 0,
            planted: 0,
            over: 0,
            anchored: 0,
            retraces: 0,
            st: st::Stepper::new(),
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
static TRACK: AtomicI32 = AtomicI32::new(-1);
/// `/proc/self/maps`, for `PROCMAP_QUERY` (`vma`).
static MAPS: AtomicI32 = AtomicI32::new(-1);

pub(crate) fn open_hidden(path: &[u8], flags: u64) -> i32 {
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

/// Make the scratch and descriptors ready for this process. False if they cannot be (the
/// host's refusal is noted).
fn resources() -> bool {
    let pid = unsafe { sc0(nr::GETPID) } as i32;
    if OWNER.load(Relaxed) == pid {
        return true;
    }
    for d in [&MEM, &PAGEMAP, &TRACK, &MAPS] {
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
    let maps = open_hidden(b"/proc/self/maps\0", 0);
    let cl = st::track_open(open_hidden);
    MEM.store(mem, Relaxed);
    PAGEMAP.store(pm, Relaxed);
    MAPS.store(maps, Relaxed);
    TRACK.store(cl.unwrap_or(-1), Relaxed);
    if mem < 0 || pm < 0 || maps < 0 || cl.is_none() {
        note_host(proto::ctl::SPIN_HOST_MEM, 0);
        return false;
    }
    OWNER.store(pid, Relaxed);
    true
}

/// The host refused something a probe needs (`proto::ctl::SPIN_HOST_*`): the first one is
/// kept for a `compute-stall` message. Never seen by the program or the log.
pub(crate) fn note_host(what: u64, errno: i64) {
    let _ = ctl().sched.spin_host.compare_exchange(
        0,
        what << 32 | (errno as u64 & 0xffff_ffff),
        Relaxed,
        Relaxed,
    );
}

/// `struct procmap_query` (Linux 6.11).
#[repr(C)]
#[derive(Default)]
pub(crate) struct ProcmapQuery {
    size: u64,
    query_flags: u64,
    query_addr: u64,
    pub vma_start: u64,
    pub vma_end: u64,
    pub vma_flags: u64,
    vma_page_size: u64,
    vma_offset: u64,
    inode: u64,
    dev_major: u32,
    dev_minor: u32,
    vma_name_size: u32,
    build_id_size: u32,
    vma_name_addr: u64,
    build_id_addr: u64,
}

/// `ProcmapQuery::vma_flags`.
pub(crate) const VMA_WRITE: u64 = 2;
pub(crate) const VMA_EXEC: u64 = 4;
pub(crate) const VMA_SHARED: u64 = 8;

/// The mapping that holds `a` (or, with `next`, the first one at or above it). A kernel
/// before 6.11 has no `PROCMAP_QUERY`: the covering mapping is read from the text of
/// `/proc/self/maps` (x86_64; arm64 needs 6.12).
pub(crate) fn vma(a: u64, next: bool) -> Option<ProcmapQuery> {
    const PROCMAP_QUERY: u64 = 0xc068_6611;
    const COVERING_OR_NEXT_VMA: u64 = 0x10;
    let mut q = ProcmapQuery {
        size: core::mem::size_of::<ProcmapQuery>() as u64,
        query_flags: if next { COVERING_OR_NEXT_VMA } else { 0 },
        query_addr: a,
        ..Default::default()
    };
    let fd = MAPS.load(Relaxed) as u64;
    let r = unsafe {
        sc3(
            nr::IOCTL,
            fd,
            PROCMAP_QUERY,
            &mut q as *mut ProcmapQuery as u64,
        )
    };
    if r == -e::ENOTTY && !next {
        return vma_text(fd, a);
    }
    (r == 0).then_some(q)
}

/// The mapping that holds `a`, from the text of `/proc/self/maps` (`start-end perms ...`).
fn vma_text(fd: u64, a: u64) -> Option<ProcmapQuery> {
    let mut buf = [0u8; 4096];
    let mut off = 0u64;
    loop {
        let n = unsafe {
            sc4(
                nr::PREAD64,
                fd,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                off,
            )
        };
        if n <= 0 {
            return None;
        }
        let b = &buf[..n as usize];
        // Whole lines only; the last partial one is read again.
        let end = b.iter().rposition(|&c| c == b'\n')? + 1;
        for line in b[..end].split(|&c| c == b'\n') {
            let mut f = line.split(|&c| c == b' ');
            let (Some(range), Some(perms)) = (f.next(), f.next()) else {
                continue;
            };
            let Some(dash) = range.iter().position(|&c| c == b'-') else {
                continue;
            };
            let (lo, hi) = (hex(&range[..dash]), hex(&range[dash + 1..]));
            if a < lo || a >= hi || perms.len() < 4 {
                continue;
            }
            let bit = |i: usize, c: u8, v: u64| if perms[i] == c { v } else { 0 };
            return Some(ProcmapQuery {
                vma_start: lo,
                vma_end: hi,
                vma_flags: bit(0, b'r', 1)
                    | bit(1, b'w', VMA_WRITE)
                    | bit(2, b'x', VMA_EXEC)
                    | bit(3, b's', VMA_SHARED),
                ..Default::default()
            });
        }
        off += end as u64;
    }
}

fn hex(s: &[u8]) -> u64 {
    s.iter()
        .map_while(|&c| (c as char).to_digit(16))
        .fold(0, |v, d| v * 16 + d as u64)
}

/// Whether a breakpoint may be planted at `a`: in a private, executable, non-writable mapping
/// outside the runtime's region. Never a shared one, whose other views and processes would see
/// it; never a writable one, where a store of the program's to the planted word (a JIT patching
/// its code) would be undone when the original word goes back.
pub(crate) fn plantable(a: u64) -> bool {
    if in_runtime(a) {
        return false;
    }
    match vma(a, false) {
        Some(q) => q.vma_flags & (VMA_WRITE | VMA_EXEC | VMA_SHARED) == VMA_EXEC,
        None => false,
    }
}

fn trace() -> &'static mut [u64] {
    unsafe { core::slice::from_raw_parts_mut((SCRATCH + TRACE_OFF) as *mut u64, TRACE_MAX) }
}

const WORD: u64 = core::mem::size_of::<Word>() as u64;

/// Write the code word at `a` through `/proc/self/mem` (which reaches read-only and
/// execute-only pages, and makes the CPU fetch the new word).
pub(crate) fn poke(a: u64, w: Word) -> bool {
    let r = unsafe {
        sc4(
            nr::PWRITE64,
            MEM.load(Relaxed) as u64,
            &w as *const Word as u64,
            WORD,
            a,
        )
    };
    if r < 0 {
        note_host(proto::ctl::SPIN_HOST_POKE, -r);
    }
    r == WORD as i64
}

pub(crate) fn peek(a: u64) -> Option<Word> {
    let mut w: Word = 0;
    let r = unsafe {
        sc4(
            nr::PREAD64,
            MEM.load(Relaxed) as u64,
            &mut w as *mut Word as u64,
            WORD,
            a,
        )
    };
    (r == WORD as i64).then_some(w)
}

/// Read code at `a` into `out`; the bytes read (fewer at the end of a mapping).
#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
pub(crate) fn peek_bytes(a: u64, out: &mut [u8]) -> usize {
    let r = unsafe {
        sc4(
            nr::PREAD64,
            MEM.load(Relaxed) as u64,
            out.as_mut_ptr() as u64,
            out.len() as u64,
            a,
        )
    };
    r.max(0) as usize
}

pub(crate) const PAGEMAP_SCAN: u64 = 0xc060_6610;

#[repr(C)]
pub(crate) struct ScanArg {
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

impl ScanArg {
    /// A scan of `[start, end)` for pages in category `cat`, with no output vector.
    pub(crate) fn new(start: u64, end: u64, flags: u64, cat: u64) -> ScanArg {
        ScanArg {
            size: core::mem::size_of::<ScanArg>() as u64,
            flags,
            start,
            end,
            walk_end: 0,
            vec: 0,
            vec_len: 0,
            max_pages: 0,
            category_inverted: 0,
            category_mask: cat,
            category_anyof_mask: 0,
            return_mask: cat,
        }
    }
}

/// `PAGEMAP_SCAN` of `[lo, hi)` for pages in category `cat` (with `flags`), appended to
/// `out` from index `n`; the new count, or None when `out` is full or the scan fails.
pub(crate) fn scan(
    pagemap: i32,
    lo: u64,
    hi: u64,
    cat: u64,
    flags: u64,
    out: &mut [u64],
    mut n: usize,
) -> Option<usize> {
    let mut start = lo;
    while start < hi {
        let mut regions = [[0u64; 3]; REGIONS];
        let mut a = ScanArg::new(start, hi, flags, cat);
        a.vec = regions.as_mut_ptr() as u64;
        a.vec_len = REGIONS as u64;
        let r = unsafe {
            sc3(
                nr::IOCTL,
                pagemap as u64,
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
    Some(n)
}

/// Pages written since the last reset, outside the runtime's region, into `out` (sorted).
/// None when there are more than `out` holds.
fn dirty_pages(out: &mut [u64]) -> Option<usize> {
    st::track_written(PAGEMAP.load(Relaxed), out)
}

fn clear_dirty() -> bool {
    st::track_reset(TRACK.load(Relaxed), PAGEMAP.load(Relaxed))
}

// ---------------------------------------------------------------------------------------
// Entry points.

/// A runtime entry other than the spin point (`on_sigsys`, `on_fault`): a probe in progress
/// ends without a trace, and the spin point stops being one.
#[inline]
pub fn enter(ts: &mut ThreadState, frame: Option<&mut Frame>) {
    let s = &ts.spin;
    if s.phase == PH_NONE && s.point == 0 && s.over == 0 {
        return;
    }
    enter_slow(ts, frame);
}

#[inline(never)]
fn enter_slow(ts: &mut ThreadState, frame: Option<&mut Frame>) {
    if let Some(f) = frame {
        if ts.spin.phase != PH_NONE || ts.spin.over != 0 {
            st::step_disarm(&mut ts.spin.st, f);
        }
    }
    st::track_end();
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

/// The address the stepper must not plant at: the spin point, while its breakpoint is there.
fn planted_point(ts: &ThreadState) -> u64 {
    if ts.spin.planted != 0 {
        ts.spin.point
    } else {
        0
    }
}

/// Every SIGTRAP first:
/// probes, single steps and the spin point. True when handled.
pub fn on_sigtrap(info: &SigInfo, frame: &mut Frame) -> bool {
    let ts = thread();
    let code = (info[1] & 0xffff_ffff) as i32;
    let pc = frame.pc();
    if code == SI_TKILL && (info[2] & 0xffff_ffff) as i32 == 1 {
        // A probe from the supervisor (PID 1). Ignored unless the thread is in guest code
        // with nothing of ours in progress.
        if config().sched & SCHED_SPIN_PROBE != 0
            && !in_runtime(pc)
            && ts.vfork == 0
            && ts.spin.phase == PH_NONE
            && ts.spin.over == 0
        {
            start(ts, frame);
        }
        return true;
    }
    if in_runtime(pc) {
        return false;
    }
    if ts.spin.planted != 0 && st::at_point(code, frame, ts.spin.point) {
        if ts.spin.phase != PH_NONE {
            ts.spin.phase = PH_NONE;
            st::track_end();
        }
        st::step_disarm(&mut ts.spin.st, frame);
        let s = &mut ts.spin;
        poke(s.point, s.orig);
        s.planted = 0;
        bump(&ctl().sched.spin_yields, 1);
        spin_yield(ts, frame, 0);
        return true;
    }
    if st::step_trap(&ts.spin.st, code, frame) {
        if ts.spin.over != 0 {
            // Stepped over the spin point: plant it again.
            st::step_disarm(&mut ts.spin.st, frame);
            ts.spin.over = 0;
            replant(ts);
            return true;
        }
        if ts.spin.phase != PH_NONE {
            step(ts, frame);
            return true;
        }
        if st::step_owned(&ts.spin.st) {
            st::step_disarm(&mut ts.spin.st, frame);
            return true;
        }
    }
    false
}

/// Plant the spin point's breakpoint again, or let the point go.
fn replant(ts: &mut ThreadState) {
    let s = &mut ts.spin;
    if s.point != 0 && st::plantable(s.point) && poke(s.point, st::BRK) {
        s.planted = 1;
    } else {
        s.point = 0;
    }
}

/// End the probe in progress: no fixed point (or one, handled by the caller).
fn end(ts: &mut ThreadState, frame: &mut Frame) {
    ts.spin.phase = PH_NONE;
    st::step_disarm(&mut ts.spin.st, frame);
    st::track_end();
}

fn abort(ts: &mut ThreadState, frame: &mut Frame) {
    end(ts, frame);
}

fn start(ts: &mut ThreadState, frame: &mut Frame) {
    let c = ctl();
    bump(&c.sched.spin_probes, 1);
    if !resources() {
        return;
    }
    if !st::track_begin(PAGEMAP.load(Relaxed)) {
        note_host(proto::ctl::SPIN_HOST_TRACK, 0);
        return;
    }
    let s = &mut ts.spin;
    trace()[0] = frame.pc();
    s.i = 0;
    s.cand = 0;
    s.period = 0;
    s.checks = 0;
    s.npages = 0;
    s.anchored = 0;
    s.retraces = st::RETRACES;
    s.phase = PH_TRACE;
    arm(ts, frame);
}

/// Arm the next step of the probe in progress. A step the stepper takes in the frame
/// itself (arm64: a branch to itself) is recorded at once.
fn arm(ts: &mut ThreadState, frame: &mut Frame) {
    while ts.spin.phase != PH_NONE {
        let p = planted_point(ts);
        match st::step_arm(&mut ts.spin.st, frame, p) {
            Arm::Armed => return,
            Arm::Refused => return abort(ts, frame),
            Arm::Taken => record(ts, frame),
        }
    }
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
fn step(ts: &mut ThreadState, frame: &mut Frame) {
    st::step_disarm(&mut ts.spin.st, frame);
    record(ts, frame);
    arm(ts, frame);
}

/// Start the trace again at `rip`, with nothing compared yet.
fn retrace(ts: &mut ThreadState, rip: u64) {
    let s = &mut ts.spin;
    trace()[0] = rip;
    s.i = 0;
    s.cand = 0;
    s.period = 0;
    s.checks = 0;
    s.npages = 0;
    s.phase = PH_TRACE;
}

/// Record the step that ended at `frame`: extend the trace, or compare at the canonical
/// position.
fn record(ts: &mut ThreadState, frame: &mut Frame) {
    bump(&ctl().sched.spin_steps, 1);
    let rip = frame.pc();
    let t = trace();
    if st::step_was_pair(&ts.spin.st) && ts.spin.anchored == 0 && ts.spin.phase == PH_TRACE {
        // The first exclusive pair of the probe: the trace starts again after it. Stops are
        // never inside a pair from here on, but the probe may have arrived inside one, and
        // that address would not come round again.
        ts.spin.anchored = 1;
        return retrace(ts, rip);
    }
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
                if s.retraces > 0 {
                    // The path after the start was not the cycle (a store-exclusive that failed
                    // once): start again here.
                    s.retraces -= 1;
                    return retrace(ts, rip);
                }
                s.cand = if rip == t[0] { i as u64 } else { 0 };
            } else if i == 2 * cand {
                let p = cand;
                s.period = p as u64;
                s.target = (2 * p + least_rotation(&t[..p])) as u64;
                s.phase = PH_ALIGN;
                if i as u64 == s.target {
                    s.phase = PH_CHECK;
                    checkpoint(ts, frame);
                }
            }
        }
        _ => {
            let p = s.period as usize;
            if rip != t[i % p] {
                if s.retraces > 0 {
                    s.retraces -= 1;
                    return retrace(ts, rip);
                }
                return abort(ts, frame);
            }
            let at_check = if s.phase == PH_ALIGN {
                i as u64 == s.target
            } else {
                (i as u64 - s.target).is_multiple_of(p as u64)
            };
            if at_check {
                s.phase = PH_CHECK;
                checkpoint(ts, frame);
            }
        }
    }
}

/// The thread is at the canonical position. Compare with the last checkpoint; on a fixed
/// point, yield; after `CHECKS` unequal ones, give up.
fn checkpoint(ts: &mut ThreadState, frame: &mut Frame) {
    let list = unsafe {
        core::slice::from_raw_parts_mut((SCRATCH + PAGES_LIST_OFF) as *mut u64, COPY_PAGES)
    };
    let saved_fp =
        unsafe { core::slice::from_raw_parts_mut((SCRATCH + FP_OFF) as *mut u8, FP_MAX) };
    let copies = SCRATCH + COPY_OFF;
    let regs = st::state_words(frame);
    let Some(fp) = st::fp_state(frame, FP_MAX) else {
        note_host(proto::ctl::SPIN_HOST_EXTRA, 0);
        return abort(ts, frame);
    };
    let s = &mut ts.spin;
    if s.checks > 0 {
        let mut now = [0u64; COPY_PAGES];
        let Some(n) = dirty_pages(&mut now) else {
            return abort(ts, frame);
        };
        let prev = &list[..s.npages as usize];
        let mut equal =
            s.checks > 1 && regs == s.regs && st::fp_equal(fp, &saved_fp[..s.fp_len as usize]);
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
            return found(ts, frame);
        }
        if s.checks > CHECKS {
            return abort(ts, frame);
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
    if !clear_dirty() {
        note_host(proto::ctl::SPIN_HOST_TRACK, 0);
        abort(ts, frame);
    }
}

/// A fixed point: the canonical position is a spin point from now on.
fn found(ts: &mut ThreadState, frame: &mut Frame) {
    let c = ctl();
    bump(&c.sched.spin_found, 1);
    bump(&c.sched.spin_yields, 1);
    end(ts, frame);
    // The last spin point, if still planted (this loop was reached from it without a runtime
    // entry), comes out: nothing stays planted across a yield.
    disarm(ts);
    let period = ts.spin.period;
    spin_yield(ts, frame, period);
}

/// Yield at the spin point (the frame's `pc`), as at a trap; then keep it a spin point.
fn spin_yield(ts: &mut ThreadState, frame: &mut Frame, period: u64) {
    let c = ctl();
    let point = frame.pc();
    // A spin point is a runtime entry at a state that is the same in every run (it was found
    // as a fixed point, or arrived at again): charge compute events here, as at a trap.
    crate::compute::enter(ts);
    ts.seq = c.seq.load(Relaxed) + 1;
    c.seq.store(ts.seq, Relaxed);
    let t = c.vclock_ns.load(Relaxed) + c.config.spin_charge_ns;
    c.vclock_ns.store(t, Relaxed);
    let g = st::state_words(frame);
    let bytes = unsafe { core::slice::from_raw_parts(g.as_ptr() as *const u8, STATE_WORDS * 8) };
    let [a2, a3, a4] = st::record_args(&g);
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns: t,
        slot: ts.slot as u16,
        kind: proto::RecKind::Preempt as u8,
        class: 0,
        nr: 2,
        args: [point, period, a2, a3, a4, 0],
        ret: 0,
        out_hash: proto::rec::hash_bytes(0, bytes),
        in_hash: 0,
    };
    crate::log::append(&rec);
    crate::sup::call_sup(Op::Yield, [0; 6]);
    crate::sys::sig::trap_exit(frame, None);
    crate::entry::check_real_mask(frame);
    crate::compute::exit(ts);
    // Arm the point: plant the breakpoint there, or, when the thread resumes at it, step its
    // instruction first and plant after.
    let Some(orig) = peek(point) else {
        return;
    };
    let s = &mut ts.spin;
    s.point = point;
    s.orig = orig;
    if frame.pc() == point {
        match st::step_arm(&mut s.st, frame, 0) {
            Arm::Armed => s.over = 1,
            // Stepped already (a branch to itself): the point is planted for the next arrival.
            Arm::Taken => replant(ts),
            Arm::Refused => s.point = 0,
        }
    } else {
        replant(ts);
    }
}
