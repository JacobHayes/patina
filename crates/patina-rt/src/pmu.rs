//! Counter preemption: preempt the thread holding the turn after N retired conditional
//! branches of guest code. Design and the reasons behind it: `crates/patina-cli/ENGINE.md`,
//! "Counter preemption".
//!
//! A *segment* is the guest code between two runtime entries. Every entry calls `enter`
//! (the segment ends, planted bytes are restored); every return to guest code calls `exit`
//! as its last action, which draws N and arms the segment:
//!
//! - small N (`Mode::Hop`): the runtime walks the guest itself, planting `int3` at the next
//!   control transfer and emulating it when hit (`hop_hit`), counting conditional branches;
//! - large N: the counter runs; `exit` reads it (`r_exit`), and each overflow (`alarm`)
//!   computes the guest count `g = R - r_exit - x`, reprograms the period when near, and
//!   lands within the margin by switching to hops for the last branches.
//!
//! `x` is the runtime's own branches inside measured windows: the overflow handler reads the
//! counter in assembly before any branch whose count is not fixed and again just before it
//! returns (`patina_sigtrap`), so its work never reaches `g`.
//!
//! Races. The overflow signal (SIGTRAP) is sent by kernel task work, which runs before the
//! kernel dequeues signals: a seccomp SIGSYS or a fault signal raised by the same instruction
//! can be pending with it. SIGTRAP has the lower number and is delivered first, the other is
//! delivered on top of it, interrupting the handler at its first instruction. `on_sigsys`
//! and `on_fault` recognise that (the interrupted address is `patina_sigtrap`): a fault returns
//! (the instruction faults again), a trapped syscall is rewound by the overflow handler so
//! that it executes again.

use crate::raw::*;
use crate::state::{config, ctl, thread, ThreadState};
use crate::sys::sig::SigInfo;
use crate::trap::{reg::*, TrapFrame};
use core::arch::global_asm;
use core::sync::atomic::{AtomicI32, Ordering::*};
use proto::ctl::*;
use proto::layout::*;
use proto::pmu::{classify, eval, mode, slice, Cti, Mode, Operand, GREG_OF, MIN_REARM, PERIOD};

pub const MAX_PLANT: usize = 64;
/// Walk at most this many instructions without a control transfer before a waypoint.
const WALK_MAX: usize = 4096;

const M_NONE: u64 = 0;
const M_HOPPING: u64 = 1;
const M_MID: u64 = 2;
const M_LONG: u64 = 3;

/// Per-thread counter state, in `ThreadState`.
#[repr(C)]
pub struct Pmu {
    /// The counter's user page (0: no counter), and its descriptor (-1: none).
    pub page: u64,
    pub fd: i64,
    pub mode: u64,
    /// 1 while a counter-measured segment runs in guest code (`r_exit` valid).
    pub armed: u64,
    /// This segment's N, the counter at its start, and the runtime branches inside it.
    pub n: u64,
    pub r_exit: u64,
    pub x: u64,
    /// Branches counted so far while hopping.
    pub g_soft: u64,
    /// The period the counter is programmed with.
    pub period: u64,
    /// A single step in progress: 1 a transfer, 2 a conditional branch.
    pub stepping: u64,
    /// Segments started by this thread (part of the draw key).
    pub segs: u64,
    /// A trapped syscall arrived on top of the overflow signal (see the module comment).
    pub resys: u64,
    /// The counter value at which the programmed overflow is due (0: not known), for the
    /// skid statistic.
    pub target: u64,
    pub nplanted: u64,
    pub planted: [u64; MAX_PLANT],
    pub orig: [u8; MAX_PLANT],
}

impl Pmu {
    pub const fn new() -> Pmu {
        Pmu {
            page: 0,
            fd: -1,
            mode: M_NONE,
            armed: 0,
            n: 0,
            r_exit: 0,
            x: 0,
            g_soft: 0,
            period: 0,
            stepping: 0,
            segs: 0,
            resys: 0,
            target: 0,
            nplanted: 0,
            planted: [0; MAX_PLANT],
            orig: [0; MAX_PLANT],
        }
    }
}

const _: () = assert!(core::mem::size_of::<ThreadState>() as u64 <= PMU_PAGE_OFF);
const OFF_PAGE: usize = core::mem::offset_of!(ThreadState, pmu) + core::mem::offset_of!(Pmu, page);

// The overflow entry. SIGTRAP arrives here (registered only with counter preemption on).
// Until the first `rdpmc`, exactly 2 conditional branches (plus the read's own, see
// `patina_pmu_read`), whatever the path: they are part of the constant `HEAD`.
global_asm!(
    ".globl patina_sigtrap",
    "patina_sigtrap:",
    "  mov rax, rsp",
    "  and rax, {altmask}",
    "  mov rax, [rax + {off}]",
    "  test rax, rax",
    "  jz 8f",
    "  cmp dword ptr [rsi + 8], 6", // si_code == TRAP_PERF
    "  jne 8f",
    "  push rbx",
    "  push r12",
    "  push r13",
    "  push r14",
    "  push r15",
    "  mov r12, rsi",
    "  mov r13, rdx",
    "  mov r14, rax",
    "  mov rdi, rax",
    "  call patina_pmu_read",
    "  mov rcx, rdx",
    "  mov rdx, rax",
    "  mov rdi, r12",
    "  mov rsi, r13",
    "  call {alarm}",
    "  test rax, rax",
    "  jz 9f",
    "  mov r15, rax",
    "  mov rdi, r14",
    "  call patina_pmu_read",
    "  add [r15], rax",
    "9:",
    "  pop r15",
    "  pop r14",
    "  pop r13",
    "  pop r12",
    "  pop rbx",
    "  ret",
    "8:",
    "  jmp {plain}",
    // patina_pmu_read(page) -> (rax = count, rdx = retries); count u64::MAX if the counter is
    // not active. Branches before the rdpmc that is used: 1 + 2 x retries; after it: 1.
    ".globl patina_pmu_read",
    "patina_pmu_read:",
    "  xor r9d, r9d",
    "2:",
    "  mov r8d, dword ptr [rdi + 8]",
    "  mov ecx, dword ptr [rdi + 12]",
    "  mov r10, qword ptr [rdi + 16]",
    "  test ecx, ecx",
    "  jz 4f",
    "  dec ecx",
    "  rdpmc",
    "  shl rdx, 32",
    "  or rax, rdx",
    "  shl rax, 16",
    "  sar rax, 16",
    "  add rax, r10",
    "  cmp r8d, dword ptr [rdi + 8]",
    "  jne 3f",
    "  mov rdx, r9",
    "  ret",
    "3:",
    "  inc r9",
    "  jmp 2b",
    "4:",
    "  mov rax, -1",
    "  mov rdx, r9",
    "  ret",
    altmask = const !(ALT_SIZE - 1),
    off = const OFF_PAGE,
    alarm = sym alarm,
    plain = sym trap_plain,
);

extern "C" {
    fn patina_sigtrap();
}

/// Read the counter: (value, retries).
#[inline(always)]
fn read(page: u64) -> (u64, u64) {
    let v: u64;
    let r: u64;
    unsafe {
        core::arch::asm!(
            "call patina_pmu_read",
            in("rdi") page,
            lateout("rax") v,
            lateout("rdx") r,
            out("rcx") _, out("r8") _, out("r9") _, out("r10") _,
        )
    };
    if v == u64::MAX {
        crate::sup::host_error(PMU_E_PAGE as i64, 0, HE_PMU);
    }
    (v, r)
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

// ---------------------------------------------------------------------------------------
// Opening, fork, exit.

/// `/proc/self/mem` of this process (hops write and read guest code through it).
static MEMFD: AtomicI32 = AtomicI32::new(-1);

fn memfd() -> u64 {
    let fd = MEMFD.load(Relaxed);
    if fd >= 0 {
        return fd as u64;
    }
    let path = b"/proc/self/mem\0";
    let r = unsafe {
        sc4(
            nr::OPENAT,
            (-100i64) as u64,
            path.as_ptr() as u64,
            2 | 0x80000,
            0,
        )
    };
    if r < 0 {
        fail(PMU_E_OPEN, (-r) as u64);
    }
    let h = hide(r);
    MEMFD.store(h as i32, Relaxed);
    h as u64
}

/// Move a descriptor to the runtime's hidden range (close-on-exec).
fn hide(fd: i64) -> i64 {
    const F_DUPFD_CLOEXEC: u64 = 1030;
    let h = unsafe { sc3(nr::FCNTL, fd as u64, F_DUPFD_CLOEXEC, FD_RT_DYN as u64) };
    unsafe { sc1(nr::CLOSE, fd as u64) };
    if h < 0 {
        fail(PMU_E_OPEN, (-h) as u64);
    }
    h
}

#[repr(C)]
struct MsgHdr {
    name: u64,
    namelen: u32,
    _p: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _p2: u32,
}

/// Ask the launcher for a counter on this thread: send a thread pidfd, get the counter.
fn broker_open(tid: i32) -> i64 {
    const PIDFD_OPEN: u64 = 434;
    const PIDFD_THREAD: u64 = 0x80;
    const SENDMSG: u64 = 46;
    const RECVMSG: u64 = 47;
    let pidfd = unsafe { sc2(PIDFD_OPEN, tid as u64, PIDFD_THREAD) };
    if pidfd < 0 {
        return pidfd;
    }
    let req = *b"patpmu01";
    let iov: [u64; 2] = [req.as_ptr() as u64, 8];
    // cmsghdr: len 20, SOL_SOCKET, SCM_RIGHTS, the descriptor.
    let cm: [u64; 3] = [20, 1 | (1 << 32), pidfd as u64];
    let m = MsgHdr {
        name: 0,
        namelen: 0,
        _p: 0,
        iov: iov.as_ptr() as u64,
        iovlen: 1,
        control: cm.as_ptr() as u64,
        controllen: 24,
        flags: 0,
        _p2: 0,
    };
    let r = unsafe { sc3(SENDMSG, FD_PMU as u64, &m as *const MsgHdr as u64, 0x4000) };
    unsafe { sc1(nr::CLOSE, pidfd as u64) };
    if r < 0 {
        return r;
    }
    let mut rep: i64 = 0;
    let riov: [u64; 2] = [&mut rep as *mut i64 as u64, 8];
    let mut rcm: [u64; 3] = [0; 3];
    let mut rm = MsgHdr {
        name: 0,
        namelen: 0,
        _p: 0,
        iov: riov.as_ptr() as u64,
        iovlen: 1,
        control: rcm.as_mut_ptr() as u64,
        controllen: 24,
        flags: 0,
        _p2: 0,
    };
    let r = unsafe {
        sc3(
            RECVMSG,
            FD_PMU as u64,
            &mut rm as *mut MsgHdr as u64,
            0x4000_0000,
        )
    };
    if r < 8 {
        return if r < 0 { r } else { -e::EIO };
    }
    if rep < 0 {
        return rep;
    }
    if rcm[0] < 20 || rcm[1] != 1 | (1 << 32) {
        return -e::EIO;
    }
    (rcm[2] & 0xffff_ffff) as i64
}

/// Open this thread's counter and map its page. Called once the thread holds the turn, at
/// thread start, in a fork child and in a new image. Nothing without counter preemption, and
/// nothing in a vfork child (no preemption there).
pub fn open(ts: &mut ThreadState) {
    if !on() || ts.vfork != 0 {
        return;
    }
    let fd = broker_open(ts.tid);
    if fd < 0 {
        fail(PMU_E_OPEN, (-fd) as u64);
    }
    let fd = hide(fd);
    let page = ts as *const ThreadState as u64 + PMU_PAGE_OFF;
    let r = unsafe {
        sc6(
            nr::MMAP,
            page,
            4096,
            PROT_READ,
            MAP_SHARED | MAP_FIXED,
            fd as u64,
            0,
        )
    };
    if r as u64 != page {
        fail(PMU_E_PAGE, (-r) as u64);
    }
    // cap_user_rdpmc and a 48-bit counter (what `patina_pmu_read` assumes).
    let caps = unsafe { core::ptr::read_volatile((page + 40) as *const u64) };
    let width = unsafe { core::ptr::read_volatile((page + 48) as *const u16) };
    if caps & 4 == 0 || width != 48 {
        fail(PMU_E_PAGE, (width as u64) << 8 | caps & 0xff);
    }
    let p = &mut ts.pmu;
    p.fd = fd;
    p.page = page;
    p.period = PERIOD;
    p.mode = M_NONE;
    p.armed = 0;
    bump(&ctl().pmu.opened, 1);
}

/// Unmap and close a counter of the thread state at `alt` (the page becomes ordinary memory
/// again, so the alternate stack can be reused).
fn drop_counter(alt: u64) {
    let t = unsafe { &mut *(alt as *mut ThreadState) };
    if t.pmu.fd >= 0 {
        unsafe { sc1(nr::CLOSE, t.pmu.fd as u64) };
    }
    if t.pmu.page != 0 || t.pmu.fd >= 0 {
        let page = alt + PMU_PAGE_OFF;
        unsafe {
            sc6(
                nr::MMAP,
                page,
                4096,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                u64::MAX,
                0,
            )
        };
    }
    t.pmu.fd = -1;
    t.pmu.page = 0;
    t.pmu.mode = M_NONE;
    t.pmu.armed = 0;
    t.pmu.nplanted = 0;
}

/// Thread exit: before the last request (another thread runs right after it).
pub fn close(ts: &mut ThreadState) {
    if ts.pmu.fd >= 0 || ts.pmu.page != 0 {
        restore_all(ts);
        drop_counter(ts as *mut ThreadState as u64);
    }
}

/// A fork child, holding the turn: the inherited counters (and `/proc/self/mem`) are the
/// parent's. Close them all (this thread's and the other threads' copies, whose alternate
/// stacks are free in the child), then open this thread's own.
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
    // The parent's planted bytes were restored at the fork's runtime entry.
    ts.pmu.nplanted = 0;
    drop_counter(ts as *mut ThreadState as u64);
    open(ts);
}

// ---------------------------------------------------------------------------------------
// Segments.

/// A runtime entry: the segment ends.
#[inline]
pub fn enter(ts: &mut ThreadState, frame: Option<&mut TrapFrame>) {
    if ts.pmu.mode == M_NONE {
        return;
    }
    enter_slow(ts, frame);
}

#[inline(never)]
fn enter_slow(ts: &mut ThreadState, frame: Option<&mut TrapFrame>) {
    ts.pmu.armed = 0;
    ts.pmu.mode = M_NONE;
    if ts.pmu.stepping != 0 {
        ts.pmu.stepping = 0;
        if let Some(f) = frame {
            f.gregs[EFL] &= !0x100;
        }
    }
    restore_all(ts);
}

/// Return to guest code at `rip`: start a segment. Last thing before the return; `tail` is
/// the number of conditional branches the caller's path executes after this returns.
#[inline]
pub fn exit(ts: &mut ThreadState, rip: u64, tail: u64) {
    if ts.pmu.page == 0 {
        return;
    }
    exit_slow(ts, rip, tail);
}

#[inline(never)]
fn exit_slow(ts: &mut ThreadState, rip: u64, tail: u64) {
    let c = ctl();
    let cfg = &c.config;
    let p = &mut ts.pmu;
    p.segs += 1;
    let key = ts.seq.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ ((ts.slot as u64) << 48)
        ^ p.segs.wrapping_mul(0xd6e8_feb8_6659_fd93);
    let n = slice(cfg, key);
    p.n = n;
    p.x = 0;
    p.armed = 0;
    p.target = 0;
    bump(&c.pmu.segments, 1);
    match mode(cfg, n) {
        Mode::Hop => {
            p.mode = M_HOPPING;
            p.g_soft = 0;
            walk(ts, rip, None);
        }
        Mode::Mid | Mode::Long => {
            let want = if mode(cfg, n) == Mode::Mid {
                n - cfg.pmu_margin
            } else {
                PERIOD
            };
            if p.period != want || mode(cfg, n) == Mode::Mid {
                set_period(p, want);
            }
            p.mode = if mode(cfg, n) == Mode::Mid {
                M_MID
            } else {
                M_LONG
            };
            bump(&c.pmu.reads, 1);
            let page = p.page;
            let (v, _) = read(page);
            // After the rdpmc: the read loop's `jne`, `read`'s failure check, the caller's tail.
            p.r_exit = v + 2 + tail;
            p.armed = 1;
        }
    }
}

fn set_period(p: &mut Pmu, period: u64) {
    const PERF_EVENT_IOC_PERIOD: u64 = 0x4008_2404;
    let r = unsafe {
        sc3(
            16,
            p.fd as u64,
            PERF_EVENT_IOC_PERIOD,
            &period as *const u64 as u64,
        )
    };
    if r < 0 {
        fail(PMU_E_PAGE, (-r) as u64);
    }
    p.period = period;
}

/// The overflow handler (from `patina_sigtrap`, after the first read). Returns the address of
/// `x` when the window must be accounted (the stub adds the second read to it), else 0.
extern "C" fn alarm(_info: *const u8, uc: *mut TrapFrame, r_a: u64, retries: u64) -> u64 {
    let ts = thread();
    let frame = unsafe { &mut *uc };
    let c = ctl();
    if ts.pmu.resys != 0 {
        // A trapped syscall was delivered on top of this signal: execute it again.
        ts.pmu.resys = 0;
        frame.gregs[RIP] -= 2;
        bump(&c.pmu.races, 1);
    }
    if ts.pmu.armed == 0 {
        return 0;
    }
    if r_a == u64::MAX {
        fail(PMU_E_PAGE, 0);
    }
    ts.pmu.armed = 0;
    // Branches between the interrupted instruction and the read: the stub's 2, the read's.
    let head = 3 + 2 * retries;
    let m = c.config.pmu_margin;
    let rip = frame.gregs[RIP];
    if !in_runtime(rip) {
        let p = &mut ts.pmu;
        let g = r_a
            .wrapping_sub(head)
            .wrapping_sub(p.r_exit)
            .wrapping_sub(p.x);
        bump(&c.pmu.alarms, 1);
        if g as i64 >= p.n as i64 || (g as i64) < 0 {
            fail(PMU_E_OVERSHOOT, g.wrapping_sub(p.n));
        }
        let r = p.n - g;
        if p.target != 0 {
            // Branches between the programmed overflow and the interrupted instruction.
            let skid = r_a.wrapping_sub(head).wrapping_sub(p.target);
            if (skid as i64) > c.pmu.max_skid.load(Relaxed) as i64 {
                c.pmu.max_skid.store(skid, Relaxed);
            }
            p.target = 0;
        }
        if r <= m || r - m < MIN_REARM {
            // Within reach: hop the last r branches.
            bump(&c.pmu.landings, 1);
            if p.period != PERIOD {
                set_period(p, PERIOD);
            }
            p.mode = M_HOPPING;
            p.g_soft = g;
            walk(ts, rip, Some(frame));
            return 0;
        }
        if r <= PERIOD + 2 * m {
            set_period(p, r - m);
            let (c0, _) = read(p.page);
            p.target = c0 + (r - m);
            bump(&c.pmu.rearms, 1);
        }
    }
    let p = &mut ts.pmu;
    p.x = p.x.wrapping_sub(r_a).wrapping_add(head + 1);
    p.armed = 1;
    &mut p.x as *mut u64 as u64
}

/// Every other SIGTRAP: our breakpoints and single steps, else the fault entry.
extern "C" fn trap_plain(sig: i32, info: *mut SigInfo, uc: *mut TrapFrame) {
    let ts = thread();
    let frame = unsafe { &mut *uc };
    let rip = frame.gregs[RIP];
    if ts.pmu.mode == M_HOPPING && !in_runtime(rip) {
        let code = unsafe { *(info as *const i32).add(2) };
        if code == 0x80 && find(ts, rip.wrapping_sub(1)).is_some() {
            hop_hit(ts, frame, rip - 1);
            return;
        }
        if code == 2 && ts.pmu.stepping != 0 {
            step_done(ts, frame);
            return;
        }
    }
    crate::fault::on_fault(sig, info, uc)
}

/// `on_sigsys` saw a frame interrupted at `patina_sigtrap`'s first instruction.
pub fn sigsys_race(ts: &mut ThreadState) {
    ts.pmu.resys = 1;
}

/// Is `rip` the overflow entry (a signal delivered on top of it, see the module comment)?
#[inline]
pub fn is_race(rip: u64) -> bool {
    rip == sigtrap_entry()
}

pub fn note_race() {
    bump(&ctl().pmu.races, 1);
}

// ---------------------------------------------------------------------------------------
// Hops.

struct Code {
    base: u64,
    n: usize,
    buf: [u8; 64],
}

impl Code {
    const fn new() -> Code {
        Code {
            base: 0,
            n: 0,
            buf: [0; 64],
        }
    }
    /// The original bytes at `ip` (at least 16 if readable), planted bytes undone.
    fn at(&mut self, ts: &ThreadState, ip: u64) -> &[u8] {
        if !(ip >= self.base && ip + 16 <= self.base + self.n as u64) {
            let r = unsafe { sc4(nr::PREAD64, memfd(), self.buf.as_mut_ptr() as u64, 64, ip) };
            self.base = ip;
            self.n = if r > 0 { r as usize } else { 0 };
            let p = &ts.pmu;
            for i in 0..p.nplanted as usize {
                let a = p.planted[i];
                if a >= ip && a < ip + self.n as u64 {
                    self.buf[(a - ip) as usize] = p.orig[i];
                }
            }
        }
        let off = (ip - self.base) as usize;
        &self.buf[off.min(self.n)..self.n]
    }
}

fn find(ts: &ThreadState, a: u64) -> Option<usize> {
    let p = &ts.pmu;
    (0..p.nplanted as usize).find(|&i| p.planted[i] == a)
}

fn poke(a: u64, b: u8) -> bool {
    let r = unsafe { sc4(18, memfd(), &b as *const u8 as u64, 1, a) };
    r == 1
}

fn restore_all(ts: &mut ThreadState) {
    let p = &mut ts.pmu;
    for i in 0..p.nplanted as usize {
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

/// Plant `int3` at `a` (whose original byte is `orig`). False if the byte cannot be written.
fn plant(ts: &mut ThreadState, a: u64, orig: u8) -> bool {
    if find(ts, a).is_some() {
        return true;
    }
    if ts.pmu.nplanted as usize == MAX_PLANT {
        restore_all(ts);
    }
    if !poke(a, 0xcc) {
        return false;
    }
    let p = &mut ts.pmu;
    p.planted[p.nplanted as usize] = a;
    p.orig[p.nplanted as usize] = orig;
    p.nplanted += 1;
    true
}

/// Walk from `ip` to the next control transfer that needs the runtime and plant there. With
/// a frame (we are in a handler that returns to `ip`), a transfer that cannot be planted is
/// single-stepped; without one (the start of a segment), the segment gives up hopping.
fn walk(ts: &mut ThreadState, start: u64, mut frame: Option<&mut TrapFrame>) {
    let mut code = Code::new();
    let mut ip = start;
    for _ in 0..WALK_MAX {
        if in_runtime(ip) {
            return; // the runtime's own code ends the segment
        }
        let bytes = code.at(ts, ip);
        let Some((len, cti)) = classify(bytes, ip) else {
            // Not decodable here: single-step it from the start, or plant a waypoint.
            if ip == start {
                if let Some(f) = frame.as_deref_mut() {
                    return step_from(ts, f, false);
                }
            }
            let b = bytes.first().copied().unwrap_or(0);
            if bytes.is_empty() || !plant(ts, ip, b) {
                return give_up(ts);
            }
            return;
        };
        match cti {
            Cti::Plain => ip += len as u64,
            Cti::Jmp(t) | Cti::Call(t) => ip = t,
            Cti::Enters => return,
            Cti::StepCond | Cti::Step if ip == start && frame.is_some() => {
                let f = frame.as_deref_mut().unwrap();
                return step_from(ts, f, cti == Cti::StepCond);
            }
            _ => {
                let b = bytes[0];
                if !plant(ts, ip, b) {
                    if ip == start {
                        if let Some(f) = frame.as_deref_mut() {
                            return step_from(
                                ts,
                                f,
                                matches!(cti, Cti::Branch(..) | Cti::StepCond),
                            );
                        }
                    }
                    return give_up(ts);
                }
                return;
            }
        }
    }
    let b = code.at(ts, ip).first().copied().unwrap_or(0);
    if !plant(ts, ip, b) {
        give_up(ts);
    }
}

/// Single-step the instruction at the frame's `rip`.
fn step_from(ts: &mut ThreadState, f: &mut TrapFrame, cond: bool) {
    f.gregs[EFL] |= 0x100;
    ts.pmu.stepping = if cond { 2 } else { 1 };
    bump(&ctl().pmu.steps, 1);
}

/// The segment cannot be followed (code that cannot be read or written): no preemption in it.
fn give_up(ts: &mut ThreadState) {
    restore_all(ts);
    ts.pmu.mode = M_NONE;
}

fn reg(f: &TrapFrame, r: u8) -> u64 {
    f.gregs[GREG_OF[r as usize & 15]]
}

fn operand(f: &TrapFrame, o: Operand, next: u64) -> u64 {
    match o {
        Operand::Reg(r) => reg(f, r),
        Operand::Mem {
            base,
            index,
            scale,
            disp,
            rip_rel,
        } => {
            let mut a = disp as u64;
            if rip_rel {
                a = a.wrapping_add(next);
            }
            if let Some(b) = base {
                a = a.wrapping_add(reg(f, b));
            }
            if let Some(i) = index {
                a = a.wrapping_add(reg(f, i) << scale);
            }
            unsafe { core::ptr::read_unaligned(a as *const u64) }
        }
    }
}

/// The guest reached a planted `int3` at `a`: emulate the transfer there.
fn hop_hit(ts: &mut ThreadState, frame: &mut TrapFrame, a: u64) {
    let c = ctl();
    let mut code = Code::new();
    let Some((len, cti)) = classify(code.at(ts, a), a) else {
        // A waypoint at an instruction the decoder does not know: step it.
        unplant(ts, a);
        frame.gregs[RIP] = a;
        return step_from(ts, frame, false);
    };
    let next = a + len as u64;
    match cti {
        Cti::Branch(cond, target) => {
            let (taken, rcx) = eval(cond, frame.gregs[EFL], frame.gregs[RCX]);
            frame.gregs[RCX] = rcx;
            frame.gregs[RIP] = if taken { target } else { next };
            bump(&c.pmu.hops, 1);
            ts.pmu.g_soft += 1;
            if ts.pmu.g_soft >= ts.pmu.n {
                return stop(ts, frame);
            }
        }
        Cti::Ret(pop) => {
            let sp = frame.gregs[RSP];
            frame.gregs[RIP] = unsafe { core::ptr::read_unaligned(sp as *const u64) };
            frame.gregs[RSP] = sp + 8 + pop as u64;
            bump(&c.pmu.emulated, 1);
        }
        Cti::IndJmp(o) => {
            frame.gregs[RIP] = operand(frame, o, next);
            bump(&c.pmu.emulated, 1);
        }
        Cti::IndCall(o) => {
            let t = operand(frame, o, next);
            let sp = frame.gregs[RSP] - 8;
            unsafe { core::ptr::write_unaligned(sp as *mut u64, next) };
            frame.gregs[RSP] = sp;
            frame.gregs[RIP] = t;
            bump(&c.pmu.emulated, 1);
        }
        Cti::Step | Cti::StepCond => {
            unplant(ts, a);
            frame.gregs[RIP] = a;
            return step_from(ts, frame, cti == Cti::StepCond);
        }
        // A waypoint (or a transfer reached by the walk's limit): continue from here.
        Cti::Plain | Cti::Jmp(_) | Cti::Call(_) | Cti::Enters => {
            unplant(ts, a);
            frame.gregs[RIP] = a;
            if matches!(cti, Cti::Plain | Cti::Enters) {
                return;
            }
            return step_from(ts, frame, false);
        }
    }
    let rip = frame.gregs[RIP];
    walk(ts, rip, Some(frame));
}

/// A single step finished.
fn step_done(ts: &mut ThreadState, frame: &mut TrapFrame) {
    frame.gregs[EFL] &= !0x100;
    let cond = ts.pmu.stepping == 2;
    ts.pmu.stepping = 0;
    if cond {
        bump(&ctl().pmu.hops, 1);
        ts.pmu.g_soft += 1;
        if ts.pmu.g_soft >= ts.pmu.n {
            return stop(ts, frame);
        }
    }
    let rip = frame.gregs[RIP];
    walk(ts, rip, Some(frame));
}

/// The N-th branch retired: preempt here, as at a trap.
fn stop(ts: &mut ThreadState, frame: &mut TrapFrame) {
    restore_all(ts);
    frame.gregs[EFL] &= !0x100;
    let short = ts.pmu.mode == M_HOPPING && ts.pmu.n <= config().pmu_margin + proto::pmu::HOP_EXTRA;
    ts.pmu.mode = M_NONE;
    ts.pmu.armed = 0;
    ts.pmu.stepping = 0;
    let c = ctl();
    let n = ts.pmu.n;
    ts.seq = c.seq.load(Relaxed) + 1;
    c.seq.store(ts.seq, Relaxed);
    let t = c.vclock_ns.load(Relaxed) + n * c.config.pmu_charge_ps / 1000;
    c.vclock_ns.store(t, Relaxed);
    bump(&c.pmu.preempts, 1);
    if short {
        bump(&c.pmu.preempts_short, 1);
    }
    let g = &frame.gregs;
    let mut words = [0u64; 18];
    words.copy_from_slice(&g[..18]);
    let bytes = unsafe { core::slice::from_raw_parts(words.as_ptr() as *const u8, 18 * 8) };
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns: t,
        slot: ts.slot as u16,
        kind: proto::RecKind::Preempt as u8,
        class: 0,
        nr: 1,
        args: [g[RIP], n, g[RCX], g[RSP], g[EFL], 0],
        ret: 0,
        out_hash: proto::rec::hash_bytes(0, bytes),
        in_hash: 0,
    };
    crate::log::append(&rec);
    crate::sup::call_sup(Op::Yield, [0; 6]);
    crate::sys::sig::trap_exit(frame, None);
    crate::entry::check_real_mask(frame);
    let rip = frame.gregs[RIP];
    exit(ts, rip, 0);
}
