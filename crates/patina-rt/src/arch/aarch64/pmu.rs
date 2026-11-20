//! Counter preemption on arm64: preempt the thread holding the turn after N retired branches
//! of guest code (`BR_RETIRED`, every branch instruction, taken or not). The policy, the
//! records and the segments are x86_64's (`crate::pmu` there, `ARCHITECTURE.md`, "Counter
//! preemption"); what differs is how the counter is read and how the last branches are hopped.
//!
//! **Reading.** The counter is read with `read()` on its descriptor (user access to the PMU
//! registers needs a host setting, and on the hosts measured it traps to the hypervisor and
//! costs as much). The kernel writes the value into the thread state, so no branch is needed
//! after the call to keep it. Every read the guest count depends on sits in assembly at a fixed
//! number of branches from guest code:
//!
//! - the return to guest code (`patina_sigreturn_read`, the end of the signal restorer and of
//!   `sigreturn_to`): when `rfd` names a counter, read it into `r_exit` (once: `rfd` is
//!   cleared), then `rt_sigreturn`. After the read's `svc`: the stub's `b.ne` and `ret`, the
//!   `b` to the stub: `TAIL` = 3.
//! - the overflow entry (`patina_sigtrap`, in `arch::stub`): no branch before its read. It
//!   falls through into the stub's `svc` (the runtime's one system-call instruction) with the
//!   return address set; any other SIGTRAP reads descriptor -1 there (it fails at once) and is
//!   told apart after the read: a hop's breakpoint costs that failed `read()` too.
//!
//! The guest's count in a window is `ra - (r_exit + TAIL)`, summed into `g` over the windows
//! of a segment (each overflow handled in guest code asks for a new read on its way back).
//!
//! **Throttling.** The kernel stops an event that interrupts more often than
//! `perf_event_max_sample_rate` allows per tick, at the overflow, until its next tick, a
//! context switch or a period change. Stopped only between the interrupted instruction and the
//! read, it loses nothing (no branch runs there); every overflow programs the period again
//! before the guest runs (`alarm`). An overflow while the runtime ran (SIGTRAP waits) is taken
//! at the guest's first instruction; the counter may have stopped before the read at the return
//! and its `TAIL`, so a window that counted no more than `TAIL` counts 0.
//!
//! **No overflow inside the runtime.** Every runtime handler blocks SIGTRAP while it runs
//! (`entry::install_handlers`), and threads start from such a handler: an overflow that comes
//! while runtime code runs stays pending until `rt_sigreturn` restores the guest's mask, and
//! is taken at the guest's first instruction, where its window is empty. An image's first
//! segment (from its entry point to its first trap) is not measured: `enter_guest` is a jump,
//! not a return with a mask, so no count starts there.
//!
//! **Hops.** Small N, and the last branches of a long one: the runtime walks the guest's
//! straight-line code to the next branch (`proto::step::flow`) and plants `brk` there (through
//! `/proc/self/mem`). At the breakpoint, a conditional or direct branch is taken in the frame
//! (`proto::step::next`, the frame's registers and flags); an indirect one (`br`, `blr`, `ret`)
//! and any branch reached with `PSTATE.BTYPE` set run natively, with a breakpoint at the
//! decoded successor, so the CPU makes its own branch-target check (`brk` is a valid target of
//! every branch type; `arch::step`'s module comment). Each counts one branch; the N-th stops
//! the thread at its successor. A raw load-exclusive in the walk ends the hops for the segment
//! (a stop between it and its store would fail the store every time): the scanner patches and
//! emulates every exclusive instruction under counters (`arch::insn`), so only code it does not
//! see (JIT) has one.
//!
//! Races: a SIGSYS or fault signal raised with the overflow signal pending is delivered on top
//! of it, at `patina_sigtrap`'s first instruction (`on_sigsys` and `on_fault` recognise it, as
//! on x86_64): a fault returns and faults again, a trapped call is rewound by the overflow
//! handler.

use crate::arch::Frame;
use crate::pmu_open::{broker_open, hide, memfd, MEMFD};
use crate::raw::*;
use crate::state::{config, ctl, thread, ThreadState};
use crate::sys::sig::{self, SigInfo};
use core::arch::global_asm;
use core::sync::atomic::Ordering::*;
use proto::ctl::*;
use proto::layout::*;
use proto::pmu::{mode, slice, Mode, MIN_REARM, PERIOD};
use proto::step::{flow, Flow, Next, Regs};

pub const MAX_PLANT: usize = 64;
/// Walk at most this many instructions without a branch before a waypoint.
const WALK_MAX: usize = 4096;
/// Branches between the read at a return to guest code and the guest's first instruction.
const TAIL: u64 = 3;

const M_NONE: u64 = 0;
const M_HOPPING: u64 = 1;
const M_MID: u64 = 2;
const M_LONG: u64 = 3;

/// `brk #0x7062` (the spin stepper's is `#0x7061`; a planted breakpoint is known by its
/// address either way).
const BRK: u32 = 0xd420_0000 | 0x7062 << 5;
const TRAP_BRKPT: i32 = 1;
const PSTATE_BTYPE: u64 = 3 << 10;

/// Per-thread counter state, in `ThreadState`. `rfd`, `r_exit` and `ra` are used by the
/// assembly below.
#[repr(C)]
pub struct Pmu {
    /// The counter's descriptor (-1: none).
    pub fd: i64,
    /// The descriptor the next return to guest code reads into `r_exit` (<= 0: no read).
    pub rfd: i64,
    /// The counter at the last return to guest code (before its `TAIL`).
    pub r_exit: u64,
    /// The counter at the overflow entry (no branch before it).
    pub ra: u64,
    pub mode: u64,
    /// 1 while a counter-measured segment runs in guest code.
    pub armed: u64,
    /// This segment's N, and its guest branches counted before the current window.
    pub n: u64,
    pub g: u64,
    /// Branches counted so far while hopping.
    pub g_soft: u64,
    /// The period the counter is programmed with.
    pub period: u64,
    /// 1 while a branch runs natively to the breakpoint at `step_to`.
    pub stepping: u64,
    pub step_to: u64,
    /// Segments started by this thread (part of the draw key).
    pub segs: u64,
    /// A trapped syscall arrived on top of the overflow signal (see the module comment).
    pub resys: u64,
    /// The counter value at which the programmed overflow is due (0: not known), for the
    /// skid statistic.
    pub target: u64,
    pub nplanted: u64,
    pub planted: [u64; MAX_PLANT],
    pub orig: [u32; MAX_PLANT],
    /// The emulated exclusive monitor (`arch::insn::exclusive`): address, size (0: none),
    /// and `Ctl::seq` at the load.
    pub excl_addr: u64,
    pub excl_size: u64,
    pub excl_seq: u64,
}

impl Pmu {
    pub const fn new() -> Pmu {
        Pmu {
            fd: -1,
            rfd: -1,
            r_exit: u64::MAX,
            ra: u64::MAX,
            mode: M_NONE,
            armed: 0,
            n: 0,
            g: 0,
            g_soft: 0,
            period: 0,
            stepping: 0,
            step_to: 0,
            segs: 0,
            resys: 0,
            target: 0,
            nplanted: 0,
            planted: [0; MAX_PLANT],
            orig: [0; MAX_PLANT],
            excl_addr: 0,
            excl_size: 0,
            excl_seq: 0,
        }
    }
}

const _: () = assert!(core::mem::size_of::<ThreadState>() as u64 <= PMU_PAGE_OFF);
const OFF_PMU: usize = core::mem::offset_of!(ThreadState, pmu);
pub(crate) const OFF_FD: usize = OFF_PMU + core::mem::offset_of!(Pmu, fd);
const OFF_RFD: usize = OFF_PMU + core::mem::offset_of!(Pmu, rfd);
const OFF_REXIT: usize = OFF_PMU + core::mem::offset_of!(Pmu, r_exit);
pub(crate) const OFF_RA: usize = OFF_PMU + core::mem::offset_of!(Pmu, ra);
const _: () = assert!(OFF_RA < 4096 && OFF_REXIT < 4096);

global_asm!(
    // The return to guest code: read the counter if asked (once), then rt_sigreturn with the
    // frame at sp.
    ".globl patina_sigreturn_read",
    "patina_sigreturn_read:",
    "  mov x9, sp",
    "  and x9, x9, #{altmask}",
    "  ldr x0, [x9, #{off_rfd}]",
    "  cmp x0, #0",
    "  b.le 1f",
    "  mov x10, #-1",
    "  str x10, [x9, #{off_rfd}]",
    "  add x1, x9, #{off_rexit}",
    "  mov x2, #8",
    "  mov x8, #{read}",
    "  bl patina_syscall",
    "1:",
    "  mov x8, #{rt_sigreturn}",
    "  b patina_syscall",
    altmask = const !(ALT_SIZE - 1),
    off_rfd = const OFF_RFD,
    off_rexit = const OFF_REXIT,
    read = const nr::READ,
    rt_sigreturn = const nr::RT_SIGRETURN,
);

extern "C" {
    fn patina_sigtrap();
}

/// The handler address registered for SIGTRAP.
pub fn sigtrap_entry() -> u64 {
    patina_sigtrap as *const () as u64
}

fn on() -> bool {
    config().pmu & PMU_ON != 0
}

fn in_runtime(a: u64) -> bool {
    (RT_BASE..RT_REGION_END).contains(&a)
}

fn bump(a: &core::sync::atomic::AtomicU64, n: u64) {
    a.store(a.load(Relaxed) + n, Relaxed);
}

fn fail(what: u64, val: u64) -> ! {
    crate::sup::host_error(what as i64, val, HE_PMU)
}

/// Read the counter now (runtime code: for the skid statistic and the check at open).
fn read_now(fd: i64) -> Option<u64> {
    let mut v: u64 = 0;
    let r = unsafe { sc3(nr::READ, fd as u64, &mut v as *mut u64 as u64, 8) };
    (r == 8).then_some(v)
}

// ---------------------------------------------------------------------------------------
// Opening, fork, exit.

/// Open this thread's counter. Called once the thread holds the turn, at thread start, in a
/// fork child and in a new image. Nothing without counter preemption, and nothing in a vfork
/// child (no preemption there).
pub fn open(ts: &mut ThreadState) {
    if !on() || ts.vfork != 0 {
        return;
    }
    let fd = broker_open(ts.tid);
    if fd < 0 {
        fail(PMU_E_OPEN, (-fd) as u64);
    }
    let fd = hide(fd);
    if read_now(fd).is_none() {
        fail(PMU_E_PAGE, 0);
    }
    let p = &mut ts.pmu;
    p.fd = fd;
    p.rfd = -1;
    p.period = PERIOD;
    p.mode = M_NONE;
    p.armed = 0;
    bump(&ctl().pmu.opened, 1);
}

/// Close the counter of the thread state at `alt`.
fn drop_counter(alt: u64) {
    let t = unsafe { &mut *(alt as *mut ThreadState) };
    if t.pmu.fd >= 0 {
        unsafe { sc1(nr::CLOSE, t.pmu.fd as u64) };
    }
    t.pmu.fd = -1;
    t.pmu.rfd = -1;
    t.pmu.mode = M_NONE;
    t.pmu.armed = 0;
    t.pmu.stepping = 0;
    t.pmu.nplanted = 0;
}

/// Thread exit: before the last request (another thread runs right after it).
pub fn close(ts: &mut ThreadState) {
    if ts.pmu.fd >= 0 {
        restore_all(ts);
        drop_counter(ts as *mut ThreadState as u64);
    }
}

/// A fork child, holding the turn: the inherited counters (and `/proc/self/mem`) are the
/// parent's. Close them all (this thread's and the other threads' copies), then open this
/// thread's own.
pub fn fork_child(ts: &mut ThreadState, others: &[u64]) {
    if !on() {
        return;
    }
    let m = MEMFD.swap(-1, Relaxed);
    if m >= 0 {
        unsafe { sc1(nr::CLOSE, m as u64) };
    }
    for &a in others {
        drop_counter(a);
    }
    // The parent's planted words were restored at the fork's runtime entry.
    ts.pmu.nplanted = 0;
    drop_counter(ts as *mut ThreadState as u64);
    open(ts);
}

// ---------------------------------------------------------------------------------------
// Segments.

/// A runtime entry: the segment ends.
#[inline]
pub fn enter(ts: &mut ThreadState, _frame: Option<&mut Frame>) {
    if ts.pmu.mode == M_NONE && ts.pmu.rfd < 0 {
        return;
    }
    enter_slow(ts);
}

#[inline(never)]
fn enter_slow(ts: &mut ThreadState) {
    ts.pmu.armed = 0;
    ts.pmu.mode = M_NONE;
    ts.pmu.rfd = -1;
    ts.pmu.stepping = 0;
    restore_all(ts);
}

/// Return to guest code at `pc` through `rt_sigreturn` (the restorer or `sigreturn_to`):
/// start a segment. Last thing before the return; the read is the return's own (`TAIL`).
#[inline]
pub fn exit(ts: &mut ThreadState, pc: u64, _tail: u64) {
    if ts.pmu.fd < 0 {
        return;
    }
    exit_slow(ts, pc);
}

#[inline(never)]
fn exit_slow(ts: &mut ThreadState, pc: u64) {
    let c = ctl();
    let cfg = &c.config;
    let p = &mut ts.pmu;
    p.segs += 1;
    let key = ts.seq.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ ((ts.slot as u64) << 48)
        ^ p.segs.wrapping_mul(0xd6e8_feb8_6659_fd93);
    let n = slice(cfg, key);
    p.n = n;
    p.g = 0;
    p.armed = 0;
    p.target = 0;
    p.stepping = 0;
    p.rfd = -1;
    bump(&c.pmu.segments, 1);
    match mode(cfg, n) {
        Mode::Hop => {
            // A short period left from a segment that ended before its overflow would raise
            // an overflow every few branches while hopping, and the kernel throttles (stops)
            // an event that interrupts too often.
            if p.period != PERIOD {
                set_period(p, PERIOD);
            }
            p.mode = M_HOPPING;
            p.g_soft = 0;
            hops_from(ts, pc, None);
        }
        m @ (Mode::Mid | Mode::Long) => {
            let want = if m == Mode::Mid {
                n - cfg.pmu_margin
            } else {
                PERIOD
            };
            if p.period != want || m == Mode::Mid {
                set_period(p, want);
            }
            p.mode = if m == Mode::Mid { M_MID } else { M_LONG };
            bump(&c.pmu.reads, 1);
            p.r_exit = u64::MAX;
            p.rfd = p.fd;
            p.armed = 1;
        }
    }
}

/// Program the period, which also starts a counter the kernel throttled. `period` is set
/// before the call.
fn set_period(p: &mut Pmu, period: u64) {
    const PERF_EVENT_IOC_PERIOD: u64 = 0x4008_2404;
    p.period = period;
    let r = unsafe {
        sc3(
            nr::IOCTL,
            p.fd as u64,
            PERF_EVENT_IOC_PERIOD,
            &period as *const u64 as u64,
        )
    };
    if r < 0 {
        fail(PMU_E_PAGE, (-r) as u64);
    }
}

/// The overflow handler (from `patina_sigtrap`, after its read into `ra`). Every overflow
/// programs the period again before it returns, so a counter the kernel stopped at this
/// overflow (throttling) counts again before any more guest code runs.
pub(crate) extern "C" fn alarm(_info: *const u8, uc: *mut Frame) {
    let ts = thread();
    let frame = unsafe { &mut *uc };
    let c = ctl();
    if ts.pmu.resys != 0 {
        // A trapped syscall was delivered on top of this signal: execute it again.
        ts.pmu.resys = 0;
        frame.set_pc(frame.pc() - crate::arch::SYSCALL_LEN);
        bump(&c.pmu.races, 1);
    }
    let p = &mut ts.pmu;
    // Stopped: no branch counted since the entry's read, though its stub's branches ran since.
    if p.ra != u64::MAX && read_now(p.fd) == Some(p.ra) {
        bump(&c.pmu.stopped, 1);
    }
    if p.armed == 0 {
        // Hopping: no overflow is needed before the next segment, which sets its own period.
        set_period(p, PERIOD);
        return;
    }
    if p.ra == u64::MAX || p.r_exit == u64::MAX {
        fail(PMU_E_PAGE, 0);
    }
    let pc = frame.pc();
    if in_runtime(pc) {
        // Runtime code runs with SIGTRAP blocked (module comment): never here.
        fail(PMU_E_MISSED, pc);
    }
    // This window: from the read at the return to the guest to the entry's read. One that
    // counted no more than the return's own `TAIL` (and no less than 0: a count that went
    // backwards fails below) holds no guest branch: its overflow came
    // while the runtime ran and was taken at the guest's first instruction, and the counter
    // may have stopped (throttled) before the return's read (module comment).
    let d = p.ra.wrapping_sub(p.r_exit);
    let w = if (0..=TAIL as i64).contains(&(d as i64)) {
        0
    } else {
        d.wrapping_sub(TAIL)
    };
    let g = p.g.wrapping_add(w);
    bump(&c.pmu.alarms, 1);
    if (g as i64) < 0 {
        fail(PMU_E_BACKWARDS, g);
    }
    if g >= p.n {
        fail(PMU_E_OVERSHOOT, g - p.n);
    }
    let r = p.n - g;
    let m = c.config.pmu_margin;
    if p.target != 0 {
        // Branches between the programmed overflow and the interrupted instruction.
        let skid = p.ra.wrapping_sub(p.target);
        if (skid as i64) > c.pmu.max_skid.load(Relaxed) as i64 {
            c.pmu.max_skid.store(skid, Relaxed);
        }
        p.target = 0;
    }
    if r <= m || r - m < MIN_REARM {
        // Within reach: hop the last r branches.
        bump(&c.pmu.landings, 1);
        set_period(p, PERIOD);
        p.mode = M_HOPPING;
        p.armed = 0;
        p.g_soft = g;
        hops_from(ts, pc, Some(frame));
        return;
    }
    if r <= PERIOD + 2 * m {
        set_period(p, r - m);
        if let Some(c0) = read_now(p.fd) {
            p.target = c0 + (r - m);
        }
        bump(&c.pmu.rearms, 1);
    } else {
        set_period(p, PERIOD);
    }
    // The next window starts at the return to the guest: read there.
    p.g = g;
    p.r_exit = u64::MAX;
    p.rfd = p.fd;
}

/// Every other SIGTRAP: the hops' breakpoints, else the fault entry.
pub(crate) extern "C" fn trap_plain(sig: i32, info: *mut SigInfo, uc: *mut Frame) {
    let ts = thread();
    let frame = unsafe { &mut *uc };
    let pc = frame.pc();
    let code = unsafe { *(info as *const i32).add(2) };
    if code <= 0 {
        // Sent by a process (the guest's own signals are virtual): from outside the sandbox,
        // which `sup::outside_check` cannot see while SIGTRAP is held.
        crate::sup::host_error(sig::SIGTRAP as i64, 0, HE_OUTSIDE_SIGNAL);
    }
    if ts.pmu.mode == M_HOPPING && !in_runtime(pc) && code == TRAP_BRKPT && find(ts, pc).is_some() {
        if ts.pmu.stepping != 0 && pc == ts.pmu.step_to {
            // A branch run natively arrived: it counts.
            ts.pmu.stepping = 0;
            unplant(ts, pc);
            if count(ts) {
                return stop(ts, frame);
            }
        }
        return hops_from(ts, pc, Some(frame));
    }
    crate::fault::on_fault(sig, info, uc)
}

/// `on_sigsys` saw a frame interrupted at `patina_sigtrap`'s first instruction.
pub fn sigsys_race(ts: &mut ThreadState) {
    ts.pmu.resys = 1;
}

/// Is `pc` the overflow entry (a signal delivered on top of it, see the module comment)?
#[inline]
pub fn is_race(pc: u64) -> bool {
    on() && pc == sigtrap_entry()
}

pub fn note_race() {
    bump(&ctl().pmu.races, 1);
}

// ---------------------------------------------------------------------------------------
// Hops.

/// Guest code as it was before any breakpoint, read through `/proc/self/mem` (execute-only
/// pages included).
struct Code {
    base: u64,
    n: usize,
    buf: [u32; 64],
}

impl Code {
    const fn new() -> Code {
        Code {
            base: 0,
            n: 0,
            buf: [0; 64],
        }
    }
    fn word(&mut self, ts: &ThreadState, a: u64) -> Option<u32> {
        if !(a >= self.base && a < self.base + 4 * self.n as u64) {
            let r = unsafe { sc4(nr::PREAD64, memfd(), self.buf.as_mut_ptr() as u64, 256, a) };
            self.base = a;
            self.n = if r > 0 { r as usize / 4 } else { 0 };
            let p = &ts.pmu;
            for i in 0..p.nplanted as usize {
                let at = p.planted[i];
                if at >= a && at < a + 4 * self.n as u64 {
                    self.buf[((at - a) / 4) as usize] = p.orig[i];
                }
            }
        }
        (a >= self.base && a < self.base + 4 * self.n as u64)
            .then(|| self.buf[((a - self.base) / 4) as usize])
    }
}

fn find(ts: &ThreadState, a: u64) -> Option<usize> {
    let p = &ts.pmu;
    (0..p.nplanted as usize).find(|&i| p.planted[i] == a)
}

fn poke(a: u64, w: u32) -> bool {
    let r = unsafe { sc4(nr::PWRITE64, memfd(), &w as *const u32 as u64, 4, a) };
    r == 4
}

fn restore_all(ts: &mut ThreadState) {
    let p = &mut ts.pmu;
    for i in (0..p.nplanted as usize).rev() {
        poke(p.planted[i], p.orig[i]);
    }
    p.nplanted = 0;
}

fn unplant(ts: &mut ThreadState, a: u64) {
    if let Some(i) = find(ts, a) {
        let p = &mut ts.pmu;
        poke(a, p.orig[i]);
        let last = p.nplanted as usize - 1;
        p.planted[i] = p.planted[last];
        p.orig[i] = p.orig[last];
        p.nplanted -= 1;
    }
}

/// Plant `brk` at `a` (whose original word is `orig`). False if the word cannot be written.
fn plant(ts: &mut ThreadState, a: u64, orig: u32) -> bool {
    if find(ts, a).is_some() {
        return true;
    }
    if in_runtime(a) {
        return false;
    }
    if ts.pmu.nplanted as usize == MAX_PLANT {
        restore_all(ts);
    }
    if !poke(a, BRK) {
        return false;
    }
    let p = &mut ts.pmu;
    p.planted[p.nplanted as usize] = a;
    p.orig[p.nplanted as usize] = orig;
    p.nplanted += 1;
    true
}

/// The segment cannot be followed (code that cannot be read or written, a raw exclusive
/// pair): no preemption in it.
fn give_up(ts: &mut ThreadState) {
    restore_all(ts);
    ts.pmu.mode = M_NONE;
    ts.pmu.stepping = 0;
}

/// One branch counted; true when it was the N-th.
fn count(ts: &mut ThreadState) -> bool {
    bump(&ctl().pmu.hops, 1);
    ts.pmu.g_soft += 1;
    ts.pmu.g_soft >= ts.pmu.n
}

/// Where the walk from an address ends.
enum Walk {
    /// The first branch, at this address, with its word.
    Branch(u64, u32),
    /// No branch within `WALK_MAX` words: a waypoint here.
    Waypoint(u64, u32),
    /// A trap comes first (the segment ends there), or the runtime's code.
    Ends,
    GiveUp,
}

fn walk(ts: &ThreadState, code: &mut Code, start: u64) -> Walk {
    let mut a = start;
    for _ in 0..WALK_MAX {
        if in_runtime(a) {
            return Walk::Ends;
        }
        let Some(w) = code.word(ts, a) else {
            return Walk::GiveUp;
        };
        match flow(w) {
            Flow::Plain if proto::step::is_load_exclusive(w) => return Walk::GiveUp,
            Flow::Plain => a += 4,
            Flow::Enters => return Walk::Ends,
            Flow::Branch | Flow::Indirect => return Walk::Branch(a, w),
        }
    }
    match code.word(ts, a) {
        Some(w) => Walk::Waypoint(a, w),
        None => Walk::GiveUp,
    }
}

/// Continue hopping from `pc`: walk to the next branch and plant there. In a handler
/// (`frame`, which returns to `pc`), a branch at `pc` itself is taken here and the walk goes
/// on from its successor.
fn hops_from(ts: &mut ThreadState, pc: u64, mut frame: Option<&mut Frame>) {
    let mut code = Code::new();
    let mut at = pc;
    loop {
        // A waypoint the thread returns to must not trap again.
        if let Some(f) = frame.as_deref() {
            at = f.pc();
            let w = code.word(ts, at).map(flow);
            if find(ts, at).is_some() && !matches!(w, Some(Flow::Branch | Flow::Indirect)) {
                unplant(ts, at);
            }
        }
        match walk(ts, &mut code, at) {
            Walk::Ends => return,
            Walk::GiveUp => return give_up(ts),
            Walk::Waypoint(a, w) => {
                if !plant(ts, a, w) {
                    give_up(ts);
                }
                return;
            }
            Walk::Branch(a, w) => {
                let Some(f) = frame.as_deref_mut().filter(|f| f.pc() == a) else {
                    if !plant(ts, a, w) {
                        give_up(ts);
                    }
                    return;
                };
                match take(ts, f, a, w) {
                    Take::Taken => {
                        bump(&ctl().pmu.emulated, 1);
                        if count(ts) {
                            return stop(ts, f);
                        }
                    }
                    Take::Native => return,
                    Take::GiveUp => return give_up(ts),
                }
            }
        }
    }
}

enum Take {
    /// Taken in the frame: `pc` is at the successor.
    Taken,
    /// The branch runs natively; a breakpoint waits at its successor.
    Native,
    GiveUp,
}

/// The branch `w` at the frame's `pc` (= `a`).
fn take(ts: &mut ThreadState, f: &mut Frame, a: u64, w: u32) -> Take {
    let btype = f.pstate & PSTATE_BTYPE != 0;
    let r = Regs {
        x: &f.regs,
        pstate: f.pstate,
    };
    let link = w >> 26 == 0b100101; // bl
    match proto::step::next(a, w, &r, &[]) {
        Next::At(s) if flow(w) == Flow::Indirect || btype => {
            // Natively, so that the CPU checks the branch target (and sets `BTYPE`).
            let mut code = Code::new();
            let Some(o) = code.word(ts, s) else {
                return Take::GiveUp;
            };
            unplant(ts, a);
            if !plant(ts, s, o) {
                return Take::GiveUp;
            }
            ts.pmu.stepping = 1;
            ts.pmu.step_to = s;
            bump(&ctl().pmu.steps, 1);
            Take::Native
        }
        Next::At(s) => {
            if link {
                f.regs[30] = a + 4;
            }
            f.set_pc(s);
            Take::Taken
        }
        Next::SelfLoop { link } if !btype => {
            if link {
                f.regs[30] = a + 4;
            }
            Take::Taken
        }
        _ => Take::GiveUp,
    }
}

/// The N-th branch retired: preempt here, as at a trap.
fn stop(ts: &mut ThreadState, frame: &mut Frame) {
    restore_all(ts);
    let short = ts.pmu.mode == M_HOPPING && ts.pmu.n <= config().pmu_margin + proto::pmu::HOP_EXTRA;
    ts.pmu.mode = M_NONE;
    ts.pmu.armed = 0;
    ts.pmu.stepping = 0;
    let c = ctl();
    let n = ts.pmu.n;
    crate::entry::next_seq(ts);
    let t = c.vclock_ns.load(Relaxed) + n * c.config.pmu_charge_ps / 1000;
    c.vclock_ns.store(t, Relaxed);
    bump(&c.pmu.preempts, 1);
    if short {
        bump(&c.pmu.preempts_short, 1);
    }
    let words = frame.regs_for_record();
    let bytes = unsafe {
        core::slice::from_raw_parts(words.as_ptr() as *const u8, core::mem::size_of_val(&words))
    };
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns: t,
        slot: ts.slot as u16,
        kind: proto::RecKind::Preempt as u8,
        class: 0,
        nr: 1,
        args: [frame.pc(), n, frame.regs[0], frame.sp(), words[33], 0],
        ret: 0,
        out_hash: proto::rec::hash_bytes(0, bytes),
        in_hash: 0,
    };
    crate::log::append(&rec);
    crate::sup::call_sup(Op::Yield, [0; 6]);
    crate::sys::sig::trap_exit(frame, None);
    crate::entry::check_real_mask(frame);
    let pc = frame.pc();
    exit(ts, pc, 0);
}
