//! Switch points from load-time plans (`--preempt points`, x86_64; ARCHITECTURE.md "Load-time
//! rewriting"). The launcher's broker answers the plan of a file this process maps executable
//! (`proto::plan`); here the plan is mapped and its traps are answered. No instruction is
//! decoded here.
//!
//! - **Mapping** (`on_map`, from the loader and the `mmap` handler): the plan's trampolines go at
//!   the load bias plus their link address (after the image; `room` reserves the space for a
//!   library `ld.so` maps), and its patched pages over the text, private and read-only, from
//!   the plan file. Its page directory and site rows are mapped in the runtime's own region.
//! - **A point**: a trampoline's `ud2` is a compute point (`compute::point`), then the program
//!   goes on after it. A `ud2` written over a `cpuid` is answered with core 0's identity
//!   (`cpuid`).
//! - **What the program sees** (`shown`): a stop in a trampoline is reported at the original
//!   address (signal frames, records); `/proc/self/maps` shows the original file for patched
//!   pages and omits trampolines (`Maps`).
//! - **Changes** (`changing`): before the program unmaps, maps over, moves or reprotects
//!   patched text or a trampoline, the image's patched pages are mapped back from the original
//!   file (counted `dropped`). Its trampolines stay, for a thread stopped in one.

use crate::raw::*;
use crate::state::{config, ctl, proc};
use crate::sys::procfs::hexv;
use core::sync::atomic::Ordering::Relaxed;
use proto::layout::{FD_PLAN, PAGE, RT_BASE, RT_REGION_END};
use proto::plan::*;

pub const MAX_IMAGES: usize = 64;

/// One image with a plan, in this address space.
#[derive(Clone, Copy)]
pub struct Img {
    /// Load bias; the trampolines' run-time address and length; the plan's header in the
    /// runtime's region (page directory and site rows at the broker's offsets).
    bias: u64,
    tramp: u64,
    tramp_len: u64,
    hdr: u64,
    w: [u64; REPLY_WORDS],
    /// The plan file's identity (its mappings), the original file (a hidden descriptor), the
    /// text's protection.
    plan_dev: u64,
    plan_ino: u64,
    orig_fd: i64,
    prot: u64,
    /// The mappings of the original file the plan was applied to: address, length, file
    /// offset. Only their patched pages are ever put back.
    maps: [(u64, u64, u64); MAX_MAPS],
    nmaps: usize,
    /// Patched pages put back; trampolines changed by the program (no longer the plan's).
    dropped: bool,
    tramp_gone: bool,
}

const MAX_MAPS: usize = 4;

pub struct Plans {
    imgs: [Img; MAX_IMAGES],
    n: usize,
}

impl Plans {
    pub const fn new() -> Plans {
        const Z: Img = Img {
            bias: 0,
            tramp: 0,
            tramp_len: 0,
            hdr: 0,
            w: [0; REPLY_WORDS],
            plan_dev: 0,
            plan_ino: 0,
            orig_fd: -1,
            prot: 0,
            maps: [(0, 0, 0); MAX_MAPS],
            nmaps: 0,
            dropped: false,
            tramp_gone: false,
        };
        Plans {
            imgs: [Z; MAX_IMAGES],
            n: 0,
        }
    }
}

#[inline]
pub fn on() -> bool {
    config().sched & proto::ctl::SCHED_POINTS != 0
}

fn count(i: usize) {
    let a = &ctl().compute.plan[i];
    a.store(a.load(Relaxed) + 1, Relaxed);
}

fn imgs() -> &'static mut [Img] {
    let p = &mut proc().plans;
    &mut p.imgs[..p.n]
}

#[repr(C)]
struct MsgHdr {
    name: u64,
    namelen: u64,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: u64,
}

/// Ask the broker for the plan of `fd` mapped from file offset `off`: its answer and the plan
/// file. A broker that cannot answer ends the run.
fn ask(fd: u64, off: u64) -> Option<([u64; REPLY_WORDS], u64)> {
    let mut req = [0u8; 16 + 4096];
    req[..8].copy_from_slice(&REQUEST);
    req[8..16].copy_from_slice(&off.to_le_bytes());
    // The program's name for the file, for the report.
    let n = fd_name(fd, &mut req[16..]);
    let iov = [req.as_ptr() as u64, 16 + n as u64];
    let cm: [u64; 3] = [20, 1 | (1 << 32), fd];
    let m = MsgHdr {
        name: 0,
        namelen: 0,
        iov: iov.as_ptr() as u64,
        iovlen: 1,
        control: cm.as_ptr() as u64,
        controllen: 24,
        flags: 0,
    };
    let r = unsafe {
        sc3(
            nr::SENDMSG,
            FD_PLAN as u64,
            &m as *const MsgHdr as u64,
            0x4000,
        )
    };
    if r < 0 {
        crate::sup::host_error(r, nr::SENDMSG, proto::ctl::HE_SYSCALL);
    }
    let mut w = [0u64; REPLY_WORDS];
    let riov = [w.as_mut_ptr() as u64, 8 * REPLY_WORDS as u64];
    let mut rcm = [0u64; 3];
    let mut rm = MsgHdr {
        name: 0,
        namelen: 0,
        iov: riov.as_ptr() as u64,
        iovlen: 1,
        control: rcm.as_mut_ptr() as u64,
        controllen: 24,
        flags: 0,
    };
    // MSG_CMSG_CLOEXEC
    let r = unsafe {
        sc3(
            nr::RECVMSG,
            FD_PLAN as u64,
            &mut rm as *mut MsgHdr as u64,
            0x4000_0000,
        )
    };
    if r != 8 * REPLY_WORDS as i64 || w[R_STATUS] as i64 > (NONE_EMPTY as i64) {
        crate::sup::host_error(r.min(0), w[R_STATUS], proto::ctl::HE_SYSCALL);
    }
    if (w[R_STATUS] as i64) < 0 {
        crate::sup::host_error(w[R_STATUS] as i64, nr::RECVMSG, proto::ctl::HE_SYSCALL);
    }
    if w[R_STATUS] != OK {
        return None;
    }
    if rcm[0] < 20 || rcm[1] != 1 | (1 << 32) {
        crate::sup::host_error(-e::EIO, nr::RECVMSG, proto::ctl::HE_SYSCALL);
    }
    Some((w, rcm[2] & 0xffff_ffff))
}

/// The kernel's name for `fd` (`/proc/self/fd/N`) into `out`: its length, 0 if none.
fn fd_name(fd: u64, out: &mut [u8]) -> usize {
    let mut lp = *b"/proc/self/fd/\0\0\0\0\0\0\0\0\0\0\0";
    crate::path::fmt_dec(&mut lp[14..], fd);
    let (p, n) = (lp.as_ptr() as u64, out.len() as u64);
    unsafe {
        sc4(
            nr::READLINKAT,
            (-100i64) as u64,
            p,
            out.as_mut_ptr() as u64,
            n,
        )
    }
    .max(0) as usize
}

/// Is `fd` a 64-bit ELF shared object or position-independent executable of this machine?
fn elf_dyn(fd: u64) -> bool {
    let mut h = [0u8; 20];
    crate::insn::scan::pread(fd, &mut h, 0)
        && &h[..5] == b"\x7fELF\x02"
        && h[16] == 3
        && h[18] == 62
}

/// Extra bytes to reserve after a mapping the program lets the runtime place: `ld.so`'s first
/// mapping of a library (offset 0, the image's whole span), which is followed by its
/// trampolines.
pub fn room(len: u64, flags: u64, fd: u64, off: u64) -> u64 {
    if !on() || off != 0 || flags & (MAP_ANONYMOUS | MAP_SHARED) != 0 || len == 0 || !elf_dyn(fd) {
        return 0;
    }
    match ask(fd, 0) {
        Some((w, plan)) => {
            unsafe { sc1(nr::CLOSE, plan) };
            w[R_TRAMP_LEN].next_multiple_of(PAGE)
        }
        None => 0,
    }
}

fn mmap(a: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> bool {
    unsafe { sc6(nr::MMAP, a, len, prot, flags, fd, off) as u64 == a }
}

fn fstat_id(fd: u64) -> (u64, u64) {
    crate::sys::fs::fstat_raw(fd as i64).map_or((0, 0), |st| (st.dev(), st.ino()))
}

fn run(img: &Img, k: u64) -> (u64, u64, u64) {
    let r = img.hdr + img.w[R_RUNS] + k * RUN_BYTES as u64;
    let g = |o| unsafe { core::ptr::read_unaligned((r + o) as *const u64) };
    (g(0), g(8), g(16))
}

/// `[a, a + len)` of `fd` at file offset `off` was just mapped executable with `prot` (and
/// `map_prot`, the protection it has now: the loader writes before it protects): apply its plan.
pub fn on_map(a: u64, len: u64, prot: u64, map_prot: u64, fd: u64, off: u64) {
    if !on() {
        return;
    }
    let Some((w, plan)) = (if prot & PROT_WRITE == 0 {
        ask(fd, off)
    } else {
        None
    }) else {
        count(proto::ctl::PLAN_UNPLANNED);
        return;
    };
    let done = apply(a, len, map_prot, fd, off, &w, plan);
    unsafe { sc1(nr::CLOSE, plan) };
    count(if done {
        proto::ctl::PLAN_APPLIED
    } else {
        proto::ctl::PLAN_UNPLANNED
    });
}

fn apply(
    a: u64,
    len: u64,
    prot: u64,
    fd: u64,
    off: u64,
    w: &[u64; REPLY_WORDS],
    plan: u64,
) -> bool {
    if w[R_VADDR] == u64::MAX {
        return false;
    }
    let bias = a.wrapping_sub(w[R_VADDR]);
    let (plan_dev, plan_ino) = fstat_id(plan);
    let p = &mut proc().plans;
    let i = match p.imgs[..p.n]
        .iter()
        .position(|m| m.bias == bias && m.plan_dev == plan_dev && m.plan_ino == plan_ino)
    {
        // Mapped again after its plan was dropped: applied afresh while its trampolines stand.
        Some(i) if p.imgs[i].tramp_gone || (p.imgs[i].nmaps == MAX_MAPS && !p.imgs[i].dropped) => {
            return false;
        }
        Some(i) => {
            if p.imgs[i].dropped {
                p.imgs[i].dropped = false;
                p.imgs[i].nmaps = 0;
            }
            i
        }
        None => {
            if p.n == MAX_IMAGES {
                return false;
            }
            let tramp = bias.wrapping_add(w[R_TRAMP_VADDR]);
            let tend = tramp.saturating_add(w[R_TRAMP_LEN]);
            if tend == u64::MAX || (tramp < RT_REGION_END && tend > RT_BASE) {
                return false;
            }
            // The original file, hidden, for putting its pages back.
            let orig_fd = unsafe { sc3(nr::FCNTL, fd, 1030, proto::layout::FD_RT_DYN as u64) };
            let fixed = MAP_PRIVATE | MAP_FIXED_NOREPLACE;
            let x = PROT_READ | PROT_EXEC;
            if orig_fd < 0 || !mmap(tramp, w[R_TRAMP_LEN], x, fixed, plan, w[R_TRAMP_OFF]) {
                if orig_fd >= 0 {
                    unsafe { sc1(nr::CLOSE, orig_fd as u64) };
                }
                return false;
            }
            let hdr = crate::state::priv_alloc(w[R_HDR], PAGE);
            if !mmap(hdr, w[R_HDR], PROT_READ, fixed, plan, 0) {
                crate::sup::host_error(-e::ENOMEM, nr::MMAP, proto::ctl::HE_SYSCALL);
            }
            p.imgs[p.n] = Img {
                bias,
                tramp,
                tramp_len: w[R_TRAMP_LEN],
                hdr,
                w: *w,
                plan_dev,
                plan_ino,
                orig_fd,
                prot: prot & !PROT_WRITE,
                maps: [(0, 0, 0); MAX_MAPS],
                nmaps: 0,
                dropped: false,
                tramp_gone: false,
            };
            p.n += 1;
            p.n - 1
        }
    };
    let img = &mut p.imgs[i];
    img.maps[img.nmaps] = (a, len, off);
    img.nmaps += 1;
    let img = *img;
    for k in 0..w[R_NRUNS] {
        let (va, n, poff) = run(&img, k);
        let (s, e) = (bias.wrapping_add(va), bias.wrapping_add(va + n));
        let (lo, hi) = (s.max(a), e.min(a + len));
        if lo < hi
            && !mmap(
                lo,
                hi - lo,
                prot,
                MAP_PRIVATE | MAP_FIXED,
                plan,
                poff + (lo - s),
            )
        {
            crate::sup::host_error(-e::ENOMEM, nr::MMAP, proto::ctl::HE_SYSCALL);
        }
    }
    true
}

/// The image and site row of a trampoline address.
fn site_at(pc: u64) -> Option<(&'static Img, u64)> {
    let img = imgs()
        .iter()
        .find(|m| !m.tramp_gone && pc >= m.tramp && pc < m.tramp + m.tramp_len)?;
    let off = (pc - img.tramp) as u32;
    let rows = img.hdr + img.w[R_SITES];
    let at = |k: u64| rows + k * SITE_BYTES as u64;
    let tramp =
        |k: u64| unsafe { core::ptr::read_unaligned((at(k) + SITE_TRAMP as u64) as *const u32) };
    // The last row whose trampoline starts at or before `off` (trampolines are in row order).
    let (mut lo, mut hi) = (0, img.w[R_NSITES]);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if tramp(mid) <= off {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    (lo > 0)
        .then(|| (img, at(lo - 1)))
        .filter(|&(_, r)| field::<u8>(r, SITE_KIND) != KIND_CPUID)
}

/// The `KIND_CPUID` site at `pc`, in an image whose plan is in force.
fn cpuid_at(pc: u64) -> bool {
    imgs().iter().filter(|m| !m.dropped).any(|img| {
        let a = pc.wrapping_sub(img.bias);
        let rows = img.hdr + img.w[R_SITES];
        let at = |k: u64| rows + k * SITE_BYTES as u64;
        let (mut lo, mut hi) = (0, img.w[R_NSITES]);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if field::<u64>(at(mid), SITE_ADDR) < a {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo < img.w[R_NSITES]
            && field::<u64>(at(lo), SITE_ADDR) == a
            && field::<u8>(at(lo), SITE_KIND) == KIND_CPUID
    })
}

/// A patched `cpuid` (`KIND_CPUID`): the host's answer, with the fields that name the core
/// as core 0's (zero). Not a scheduling event: no record, no virtual time. (Plans exist on
/// x86_64 only.)
#[cfg(not(target_arch = "x86_64"))]
fn cpuid(_: &mut crate::arch::Frame) {}
#[cfg(target_arch = "x86_64")]
fn cpuid(frame: &mut crate::arch::Frame) {
    use crate::arch::reg::*;
    let (leaf, sub) = (frame.gregs[RAX] as u32, frame.gregs[RCX] as u32);
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    let (mut a, mut b, mut c, mut d) = (r.eax, r.ebx, r.ecx, r.edx);
    match leaf {
        // Initial APIC id.
        1 => b &= 0x00ff_ffff,
        // x2APIC id (topology leaves).
        0xb | 0x1f => d = 0,
        // Hybrid core type and model.
        0x1a => a = 0,
        // Extended APIC id, compute unit id, node id.
        0x8000_001e => {
            a = 0;
            b &= !0xff;
            c &= !0xff;
        }
        // Extended APIC id (AMD extended topology).
        0x8000_0026 => d = 0,
        _ => {}
    }
    for (reg, v) in [(RAX, a), (RBX, b), (RCX, c), (RDX, d)] {
        frame.gregs[reg] = v as u64;
    }
    count(proto::ctl::PLAN_CPUID);
}

fn field<T: Copy>(row: u64, o: usize) -> T {
    unsafe { core::ptr::read_unaligned((row + o as u64) as *const T) }
}

/// Where the program is when its counter stopped at `pc`: `pc` itself unless that is a
/// trampoline address (`proto::plan::shown`).
pub fn shown(pc: u64) -> u64 {
    if proc().plans.n == 0 {
        return pc;
    }
    let Some((img, row)) = site_at(pc) else {
        return pc;
    };
    let t = img.tramp + field::<u32>(row, SITE_TRAMP) as u64;
    let kind = field::<u8>(row, SITE_KIND);
    let target = if kind == KIND_JUMP {
        let rel = crate::guest::get::<i32>(t + JUMP_ROW + 1).unwrap_or(0);
        (t + JUMP_ROW + 5).wrapping_add(rel as i64 as u64)
    } else {
        0
    };
    proto::plan::shown(
        field::<u64>(row, SITE_ADDR) + img.bias,
        field::<u8>(row, SITE_LEN) as u64,
        kind,
        field::<u16>(row, SITE_COPY) as u64,
        field::<u16>(row, SITE_TRAP) as u64,
        target,
        pc - t,
    )
}

/// A fault in program code: the trap of a trampoline is a compute point; a trampoline's count
/// that cannot reach the cell is the program's doing (`compute-cell`).
pub fn try_point(
    frame: &mut crate::arch::Frame,
    sig: i32,
    info: &crate::sys::sig::SigInfo,
) -> bool {
    let pc = frame.pc();
    if proc().plans.n == 0 {
        return false;
    }
    let Some((img, row)) = site_at(pc) else {
        if sig as u64 == crate::sys::sig::SIGILL && cpuid_at(pc) {
            cpuid(frame);
            frame.set_pc(pc + 2);
            return true;
        }
        return false;
    };
    if sig as u64 == crate::sys::sig::SIGSEGV && info[2] & !(PAGE - 1) == CELL {
        crate::compute::cell_lost(-e::EFAULT, false);
    }
    let trap =
        img.tramp + field::<u32>(row, SITE_TRAMP) as u64 + field::<u16>(row, SITE_TRAP) as u64;
    if sig as u64 != crate::sys::sig::SIGILL || pc != trap {
        return false;
    }
    count(proto::ctl::PLAN_POINTS);
    crate::compute::point(crate::state::thread(), frame, shown(pc));
    frame.set_pc(pc + 2);
    true
}

/// Before the program changes `[a, a + len)` (unmaps, maps over, moves, reprotects): an image
/// whose patched pages or trampolines that touches goes back to the original file's pages.
pub fn changing(a: u64, len: u64) {
    let end = a.saturating_add(len);
    for img in imgs().iter_mut() {
        if !img.tramp_gone && a < img.tramp + img.tramp_len && img.tramp < end {
            img.tramp_gone = true;
        }
        if img.dropped || !patched(img).any(|(s, e, _)| a < e && s < end) {
            continue;
        }
        for (s, e, off) in patched(img) {
            if !mmap(
                s,
                e - s,
                img.prot,
                MAP_PRIVATE | MAP_FIXED,
                img.orig_fd as u64,
                off,
            ) {
                crate::sup::host_error(-e::ENOMEM, nr::MMAP, proto::ctl::HE_SYSCALL);
            }
            // The instruction channels' patches there (`rdrand`...) are written again.
            crate::insn::patch::rewrite(s, e - s, img.prot);
        }
        img.dropped = true;
        count(proto::ctl::PLAN_DROPPED);
    }
}

/// The patched pages of `img` as mapped: start, end, and the original file's offset there.
fn patched(img: &Img) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
    img.maps[..img.nmaps]
        .iter()
        .flat_map(move |&(a, len, off)| {
            (0..img.w[R_NRUNS]).filter_map(move |k| {
                let (va, n, _) = run(img, k);
                let (s, e) = (img.bias.wrapping_add(va), img.bias.wrapping_add(va + n));
                let (lo, hi) = (s.max(a), e.min(a + len));
                (lo < hi).then_some((lo, hi, off + (lo - a)))
            })
        })
}

/// Memory made executable that has no plan (anonymous or shared, or made executable after it
/// was mapped): no points there.
pub fn unplanned() {
    if on() {
        count(proto::ctl::PLAN_UNPLANNED);
    }
}

/// `/proc/self/maps` as the program would see it without plans, one line at a time
/// (`procfs`): a trampoline's line is left out, a patched page's names the original file (its
/// device, inode, offset and path), and it joins the original file's lines around it.
pub struct Maps {
    /// The line held back to join the next: start, end, offset, device, inode, whether it was
    /// rewritten, its permissions, its path.
    held: bool,
    start: u64,
    end: u64,
    off: u64,
    dev: (u64, u64),
    ino: u64,
    subst: bool,
    perms: [u8; 4],
    path: [u8; 4096],
    plen: usize,
}

impl Maps {
    pub fn new() -> Maps {
        Maps {
            held: false,
            start: 0,
            end: 0,
            off: 0,
            dev: (0, 0),
            ino: 0,
            subst: false,
            perms: [0; 4],
            path: [0; 4096],
            plen: 0,
        }
    }

    /// Take one line of the kernel's map; `emit` gets each finished line.
    pub fn feed(&mut self, line: &[u8], emit: &mut dyn FnMut(&[u8])) {
        if proc().plans.n == 0 {
            return emit(line);
        }
        let mut f = line.splitn(6, |&c| c == b' ');
        let (range, perms, off, dev, ino) = (
            f.next().unwrap_or(b""),
            f.next().unwrap_or(b""),
            f.next().unwrap_or(b""),
            f.next().unwrap_or(b""),
            f.next().unwrap_or(b""),
        );
        let rest = f.next().unwrap_or(b"");
        let mut path = &rest[rest.iter().position(|&c| c != b' ').unwrap_or(rest.len())..];
        let dash = range.iter().position(|&c| c == b'-').unwrap_or(0);
        let colon = dev.iter().position(|&c| c == b':').unwrap_or(0);
        let (start, end) = (hexv(&range[..dash]), hexv(&range[dash + 1..]));
        let (mut d, mut i, mut o) = (
            (hexv(&dev[..colon]), hexv(&dev[colon + 1..])),
            crate::path::dec(ino),
            hexv(off),
        );
        let mut name = [0u8; 4096];
        let mut subst = false;
        let mm = crate::path::makedev(d.0, d.1);
        let ours = |m: &&Img| m.plan_dev == mm && m.plan_ino == i && mm != 0;
        let tramp = |m: &&Img| start >= m.tramp && start < m.tramp + m.tramp_len;
        if imgs().iter().filter(ours).any(|m| tramp(&m)) {
            return;
        }
        let at = imgs().iter().filter(ours).find_map(|m| {
            patched(m)
                .find(|p| p.0 <= start && start < p.1)
                .map(|p| (m, p))
        });
        if let Some((img, (s0, _, off0))) = at {
            let st = crate::sys::fs::fstat_raw(img.orig_fd);
            let n = fd_name(img.orig_fd as u64, &mut name);
            if let (Some(st), true) = (st, n > 0) {
                d = (
                    crate::path::dev_major(st.dev()),
                    crate::path::dev_minor(st.dev()),
                );
                i = st.ino();
                o = off0 + (start - s0);
                path = &name[..n];
                subst = true;
            }
        }
        let joins = self.held
            && (self.subst || subst)
            && self.end == start
            && self.perms[..] == perms[..perms.len().min(4)]
            && self.dev == d
            && self.ino == i
            && &self.path[..self.plen] == path
            && self.off + (self.end - self.start) == o;
        if joins {
            self.end = end;
            self.subst = true;
            return;
        }
        self.flush(emit);
        *self = Maps {
            held: true,
            start,
            end,
            off: o,
            dev: d,
            ino: i,
            subst,
            perms: [0; 4],
            path: [0; 4096],
            plen: path.len().min(4096),
        };
        self.perms[..perms.len().min(4)].copy_from_slice(&perms[..perms.len().min(4)]);
        self.path[..self.plen].copy_from_slice(&path[..self.plen]);
    }

    /// The line held back, if any.
    pub fn flush(&mut self, emit: &mut dyn FnMut(&[u8])) {
        if !self.held {
            return;
        }
        self.held = false;
        // The kernel's format (`show_map_vma`): `%08lx-%08lx %s %08llx %02x:%02x %lu `, then a
        // path from column 73.
        let mut b = [0u8; 4200];
        let mut w = crate::sys::procfs::W::new(&mut b);
        w.hex(self.start, 8)
            .c(b'-')
            .hex(self.end, 8)
            .c(b' ')
            .s(&self.perms)
            .c(b' ');
        w.hex(self.off, 8)
            .c(b' ')
            .hex(self.dev.0, 2)
            .c(b':')
            .hex(self.dev.1, 2);
        w.c(b' ').u(self.ino).c(b' ');
        if self.plen > 0 {
            while w.n < 72 {
                w.c(b' ');
            }
            w.c(b' ').s(&self.path[..self.plen]);
        }
        emit(w.bytes());
    }
}
