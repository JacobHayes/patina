//! Switch points from load-time plans (load-time points; ARCHITECTURE.md "Load-time
//! rewriting"). The launcher's broker answers the plan of a file this process maps executable
//! (`proto::plan`); here the plan is mapped and its traps are answered. No instruction is
//! decoded here.
//!
//! - **Mapping** (`on_map`, from the loader and the `mmap` handler): the plan's trampolines go at
//!   the load bias plus their link address (after the image; `room` reserves the space for a
//!   library `ld.so` maps), and its patched pages over the text, private and read-only, from
//!   the plan file. Its page directory and site rows are mapped in the runtime's own region.
//! - **A point**: a trampoline's trap (`hlt`, arm64 `udf`) is a compute point (`compute::point`), then the program
//!   goes on after it; a switch first walks on (`spin::walk`). A `ud2` written over a `cpuid`
//!   is answered with core 0's identity (`cpuid`). A trap at an interior boundary of a group
//!   (a jump there from code the rewriter could not see) resumes at the copy of that
//!   instruction (`entry`).
//! - **What the program sees** (`shown`): a stop in a trampoline is reported at the original
//!   address (signal frames, records); `/proc/self/maps` shows the original file for patched
//!   pages and omits trampolines (`Maps`).
//! - **Changes** (`changing`): before the program unmaps, maps over, moves or reprotects
//!   patched text, the patched pages it touches (grown to whole patches) are mapped back from
//!   the original file and leave the plan (counted `restored`, or `dropped` when none is left);
//!   the rest keep their points. A change to a trampoline puts back every patched page. The
//!   trampolines stay, for a thread stopped in one. A later mapping of the file at the same
//!   place takes the plan again for what it covers.

use crate::raw::*;
use crate::state::{config, ctl, proc};
use crate::sys::procfs::hexv;
use core::sync::atomic::Ordering::Relaxed;
use proto::layout::{FD_PLAN, MMAP_FLOOR, PAGE, RT_BASE, RT_REGION_END};
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
    /// Ranges whose patched pages were put back (sorted, disjoint, page-aligned; `ALL` when
    /// every one was): no longer the plan's, so neither put back again nor answered by its
    /// entries. Trampolines changed by the program (no longer the plan's).
    restored: [(u64, u64); MAX_RESTORED],
    nrestored: usize,
    tramp_gone: bool,
}

const MAX_MAPS: usize = 4;
const MAX_RESTORED: usize = 16;
const ALL: (u64, u64) = (0, u64::MAX);

pub struct Plans {
    imgs: [Img; MAX_IMAGES],
    n: usize,
    /// An interpreter's line points took over (`lines`): no mapping takes a plan any more.
    lines: bool,
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
            restored: [(0, 0); MAX_RESTORED],
            nrestored: 0,
            tramp_gone: false,
        };
        Plans {
            imgs: [Z; MAX_IMAGES],
            n: 0,
            lines: false,
        }
    }
}

#[inline]
pub fn on() -> bool {
    config().sched & proto::ctl::SCHED_POINTS != 0
}

pub fn count(i: usize) {
    count_n(i, 1);
}

pub fn count_n(i: usize, n: u64) {
    let a = &ctl().compute.plan[i];
    a.store(a.load(Relaxed) + n, Relaxed);
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
    // MSG_CMSG_CLOEXEC. The plan arrives at the lowest free number, closed before the
    // program runs again: any number, whatever the program's limit.
    let r = crate::fdlim::raised(|| unsafe {
        sc3(
            nr::RECVMSG,
            FD_PLAN as u64,
            &mut rm as *mut MsgHdr as u64,
            0x4000_0000,
        )
    });
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
pub(crate) fn fd_name(fd: u64, out: &mut [u8]) -> usize {
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
        && u16::from_le_bytes([h[18], h[19]]) == MACHINE
}

/// This machine's ELF number, its trampolines' trap (x86_64 `hlt`, a general protection
/// fault in user mode: `SIGSEGV` from the kernel, at it, no address; arm64 `udf`: `SIGILL`)
/// and its length, and the
/// protection bits a trampoline keeps from its text (arm64: `PROT_BTI`, so that a copied
/// indirect branch sets the same branch type as in place).
#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = 62;
#[cfg(target_arch = "x86_64")]
const TRAP_LEN: u64 = 1;
#[cfg(target_arch = "x86_64")]
fn is_trap(sig: i32, info: &crate::sys::sig::SigInfo) -> bool {
    sig as u64 == crate::sys::sig::SIGSEGV && info[1] as u32 as i32 == 0x80 && info[2] == 0
}
#[cfg(target_arch = "x86_64")]
const KEEP: u64 = 0;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = 183;
#[cfg(target_arch = "aarch64")]
const TRAP_LEN: u64 = 4;
#[cfg(target_arch = "aarch64")]
fn is_trap(sig: i32, _: &crate::sys::sig::SigInfo) -> bool {
    sig as u64 == crate::sys::sig::SIGILL
}
#[cfg(target_arch = "aarch64")]
const KEEP: u64 = crate::arch::insn::PROT_BTI;

/// Extra bytes to reserve after a mapping the program lets the runtime place: `ld.so`'s first
/// mapping of a library (offset 0, the image's whole span), which is followed by its
/// trampolines. On arm64, where libraries' segments are aligned to more than a page, `ld.so`
/// first reserves the span (`PROT_NONE`, anonymous) and maps the file inside it; the rewriter
/// puts their trampolines past the reservation, within a branch's reach (128 MiB) of the text.
pub fn room(len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> u64 {
    if proc().plans.lines {
        return 0;
    }
    if cfg!(target_arch = "aarch64") && on() && prot == 0 && flags & MAP_ANONYMOUS != 0 {
        return 1 << 27;
    }
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

/// Map the first `n` trampoline runs of `plan` at `tramp`; when one cannot be, those before it
/// are unmapped and the answer is false.
fn tramps(tramp: u64, w: &[u64; REPLY_WORDS], plan: u64, n: u64, keep: u64) -> bool {
    let row = |k: u64| {
        let mut b = [0u8; RUN_BYTES];
        let ok = crate::insn::scan::pread(plan, &mut b, w[R_TRUNS] + k * RUN_BYTES as u64);
        let g = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        ok.then(|| (tramp + g(0), g(8), g(16)))
    };
    let x = PROT_READ | PROT_EXEC | keep;
    for k in 0..n {
        let mapped = row(k).is_some_and(|(a, len, off)| {
            mmap(a, len, x, MAP_PRIVATE | MAP_FIXED_NOREPLACE, plan, off)
        });
        if !mapped {
            for (a, len, _) in (0..k).filter_map(row) {
                unsafe { sc2(nr::MUNMAP, a, len) };
            }
            return false;
        }
    }
    true
}

/// Row `k` of the page directory (`R_RUNS`) or the trampoline directory (`R_TRUNS`).
fn run_in(img: &Img, dir: usize, k: u64) -> (u64, u64, u64) {
    let r = img.hdr + img.w[dir] + k * RUN_BYTES as u64;
    let g = |o| unsafe { core::ptr::read_unaligned((r + o) as *const u64) };
    (g(0), g(8), g(16))
}

fn run(img: &Img, k: u64) -> (u64, u64, u64) {
    run_in(img, R_RUNS, k)
}

/// `[a, a + len)` of `fd` at file offset `off` was just mapped executable with `prot` (and
/// `map_prot`, the protection it has now: the loader writes before it protects): apply its plan.
pub fn on_map(a: u64, len: u64, prot: u64, map_prot: u64, fd: u64, off: u64) {
    if !on() || proc().plans.lines {
        return;
    }
    let t0 = crate::profile::now_ns();
    let Some((w, plan)) = (if prot & PROT_WRITE == 0 {
        ask(fd, off)
    } else {
        None
    }) else {
        count(proto::ctl::PLAN_UNPLANNED);
        crate::profile::record_plan_on_map(crate::profile::now_ns().saturating_sub(t0));
        return;
    };
    let done = apply(a, len, map_prot, fd, off, &w, plan);
    unsafe { sc1(nr::CLOSE, plan) };
    count(if done {
        proto::ctl::PLAN_APPLIED
    } else {
        proto::ctl::PLAN_UNPLANNED
    });
    crate::profile::record_plan_on_map(crate::profile::now_ns().saturating_sub(t0));
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
        // Mapped again (after a change put pages back, or another part of the file): the plan
        // applies to the new mapping while its trampolines stand.
        Some(i) if p.imgs[i].tramp_gone => return false,
        Some(i) => {
            prune(&mut p.imgs[i]);
            let m = &p.imgs[i];
            if !covers(m, a, len, off) && m.nmaps == MAX_MAPS {
                return false;
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
            // Trampolines before an image the allocator placed (arm64), below its cursor: it
            // goes on below them. (An executable's are below its fixed base, out of its range.)
            let cursor = proc().mmap_cursor;
            let low = if tramp < a && tramp >= MMAP_FLOOR {
                tramp.min(cursor)
            } else {
                cursor
            };
            // The original file, hidden, for putting its pages back.
            let orig_fd = crate::fdlim::raised(|| unsafe {
                sc3(nr::FCNTL, fd, 1030, proto::layout::FD_RT_DYN as u64)
            });
            let fixed = MAP_PRIVATE | MAP_FIXED_NOREPLACE;
            if orig_fd < 0 || !tramps(tramp, w, plan, w[R_NTRUNS], prot & KEEP) {
                if orig_fd >= 0 {
                    unsafe { sc1(nr::CLOSE, orig_fd as u64) };
                }
                return false;
            }
            proc().mmap_cursor = low;
            let p = &mut proc().plans;
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
                restored: [(0, 0); MAX_RESTORED],
                nrestored: 0,
                tramp_gone: false,
            };
            p.n += 1;
            p.n - 1
        }
    };
    let img = &mut p.imgs[i];
    if !covers(img, a, len, off) {
        img.maps[img.nmaps] = (a, len, off);
        img.nmaps += 1;
    }
    // What the new mapping covers is the plan's again, but for a patch that would be cut by a
    // page left original beside it (x86_64: a patch can cross a page): those pages of the new
    // mapping keep the original code and are marked put back.
    let (a0, a1) = (a & !(PAGE - 1), (a + len + PAGE - 1) & !(PAGE - 1));
    let (lo, hi) = revived(&*img, a0, a1);
    let ok = if lo < hi {
        (a0 == lo || mark(img, a0, lo)) && (hi == a1 || mark(img, hi, a1)) && unrestore(img, lo, hi)
    } else {
        mark(img, a0, a1)
    };
    if !ok {
        // No room to track what stays put back: every patched page goes back.
        restore(img, ALL.0, ALL.1);
        return true;
    }
    let img = *img;
    for k in 0..w[R_NRUNS] {
        let (va, n, poff) = run(&img, k);
        let (s, e) = (bias.wrapping_add(va), bias.wrapping_add(va + n));
        live(&img, s.max(lo), e.min(hi), &mut |lo, hi| {
            if !mmap(
                lo,
                hi - lo,
                prot,
                MAP_PRIVATE | MAP_FIXED,
                plan,
                poff + (lo - s),
            ) {
                crate::sup::host_error(-e::ENOMEM, nr::MMAP, proto::ctl::HE_SYSCALL);
            }
        });
    }
    true
}

/// Whether `pc` is in an image's trampolines (where a walk does not stop: `spin::walk`), not
/// counting trampolines the program changed (its own code now). The span from the first
/// trampoline to the last holds the image itself when some are before it (arm64): only the
/// mapped trampoline runs count.
pub fn in_tramp(pc: u64) -> bool {
    imgs().iter().any(|m| {
        !m.tramp_gone
            && pc >= m.tramp
            && pc < m.tramp + m.tramp_len
            && (0..m.w[R_NTRUNS]).any(|k| {
                let (off, n, _) = run_in(m, R_TRUNS, k);
                pc - m.tramp >= off && pc - m.tramp < off + n
            })
    })
}

/// The image and site row of a trampoline address.
fn site_at(pc: u64) -> Option<(&'static Img, u64)> {
    let img = imgs()
        .iter()
        .find(|m| !m.tramp_gone && pc >= m.tramp && pc < m.tramp + m.tramp_len)?;
    let off = (pc - img.tramp) as u32;
    let rows = img.hdr + img.w[R_SITES];
    let at = |k: u64| rows + k * SITE_BYTES as u64;
    // The last row whose trampoline starts at or before `off` (rows are in trampoline order).
    let (mut lo, mut hi) = (0, img.w[R_NSITES]);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if field::<u32>(at(mid), SITE_TRAMP) <= off {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let row = at(lo.checked_sub(1)?);
    let end = field::<u32>(row, SITE_TRAMP) + field::<u16>(row, SITE_TRAMP_LEN) as u32;
    (off < end).then_some((img, row))
}

/// The entry row for `pc` of kind `kind`, in an image whose plan is in force there.
fn entry_at(pc: u64, kind: u8) -> Option<(&'static Img, u64)> {
    imgs().iter().filter(|m| !restored(m, pc)).find_map(|img| {
        let a = pc.wrapping_sub(img.bias);
        let rows = img.hdr + img.w[R_ENTRIES];
        let at = |k: u64| rows + k * ENTRY_BYTES as u64;
        let (mut lo, mut hi) = (0, img.w[R_NENTRIES]);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if field::<u64>(at(mid), ENTRY_ADDR) < a {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        (lo < img.w[R_NENTRIES]
            && field::<u64>(at(lo), ENTRY_ADDR) == a
            && field::<u8>(at(lo), ENTRY_KIND) == kind)
            .then(|| (img, at(lo)))
    })
}

/// Whether a `SIGTRAP` at `pc` is a plan's own: a jump onto an interior boundary's `int3`
/// (`entry`). Reads only.
pub fn owns_sigtrap(pc: u64, info: &crate::sys::sig::SigInfo) -> bool {
    const SI_KERNEL: i32 = 0x80;
    info[1] as u32 as i32 == SI_KERNEL
        && proc().plans.n != 0
        && entry_at(pc.wrapping_sub(1), KIND_INTERIOR).is_some_and(|(img, _)| !img.tramp_gone)
}

/// A trap the plan answers in place: a `cpuid` (`SIGILL` at its `ud2`), or a jump into an
/// interior boundary of a group (from the kernel: `int3` a `SIGTRAP` after it, the others a
/// `SIGSEGV` at it with no address), which resumes at the copy of that instruction in the
/// trampoline with every register as it was: the program goes on as unpatched. Neither is a
/// scheduling event (no record, no virtual time); each is counted.
fn entry(frame: &mut crate::arch::Frame, sig: i32, info: &crate::sys::sig::SigInfo) -> bool {
    use crate::sys::sig::{SIGILL, SIGSEGV, SIGTRAP};
    const SI_KERNEL: i32 = 0x80;
    let (pc, code) = (frame.pc(), info[1] as u32 as i32);
    let (at, kind) = match sig as u64 {
        SIGILL => (pc, KIND_CPUID),
        SIGTRAP if code == SI_KERNEL => (pc.wrapping_sub(1), KIND_INTERIOR),
        SIGSEGV if code == SI_KERNEL && info[2] == 0 => (pc, KIND_INTERIOR),
        _ => return false,
    };
    let Some((img, row)) = entry_at(at, kind) else {
        return false;
    };
    if kind == KIND_CPUID {
        cpuid(frame);
        frame.set_pc(pc + 2);
    } else if img.tramp_gone {
        return false;
    } else {
        frame.set_pc(img.tramp + field::<u32>(row, ENTRY_TO) as u64);
        count(proto::ctl::PLAN_INTERIOR);
    }
    true
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

/// Where the program is when it stopped at `pc`: `pc` itself unless that is a trampoline
/// address (`proto::plan::shown`).
pub fn shown(pc: u64) -> u64 {
    if proc().plans.n == 0 {
        return pc;
    }
    let Some((img, row)) = site_at(pc) else {
        return pc;
    };
    let t = img.tramp + field::<u32>(row, SITE_TRAMP) as u64;
    let kind = field::<u8>(row, SITE_KIND);
    let addr = field::<u64>(row, SITE_ADDR) + img.bias;
    #[cfg(target_arch = "aarch64")]
    {
        // The row of a branch site is `b <target>`.
        let copy = field::<u16>(row, SITE_COPY) as u64;
        let b = crate::guest::get::<u32>(t + copy).unwrap_or(0);
        let target = (t + copy).wrapping_add(((b << 6) as i32 >> 4) as i64 as u64);
        proto::plan::shown_a64(addr, kind, copy, target, pc - t)
    }
    #[cfg(target_arch = "x86_64")]
    let target = if kind == KIND_JUMP {
        let jump_row = if config().coverage != 0 {
            JUMP_ROW_COV
        } else {
            JUMP_ROW
        };
        let rel = crate::guest::get::<i32>(t + jump_row + 1).unwrap_or(0);
        (t + jump_row + 5).wrapping_add(rel as i64 as u64)
    } else {
        0
    };
    #[cfg(target_arch = "x86_64")]
    proto::plan::shown(
        addr,
        field::<u8>(row, SITE_LEN) as u64,
        kind,
        field::<u16>(row, SITE_COPY) as u64,
        field::<u16>(row, SITE_TRAP) as u64,
        target,
        pc - t,
    )
}

/// A fault in program code: the trap of a trampoline is a compute point; a trampoline's count
/// that cannot reach the cell is the program's doing (`compute-cell`); else `entry`.
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
        let t0 = crate::profile::now_ns();
        let ok = entry(frame, sig, info);
        if ok {
            crate::profile::record_plan_entry(crate::profile::now_ns().saturating_sub(t0));
        }
        return ok;
    };
    if sig as u64 == crate::sys::sig::SIGSEGV
        && (info[2] & !(PAGE - 1) == CELL
            || (config().coverage != 0
                && (COVERAGE_MAP..COVERAGE_MAP + COVERAGE_SIZE).contains(&info[2])))
    {
        crate::compute::cell_lost(-e::EFAULT, false);
    }
    let trap =
        img.tramp + field::<u32>(row, SITE_TRAMP) as u64 + field::<u16>(row, SITE_TRAP) as u64;
    if !is_trap(sig, info) || pc != trap {
        return false;
    }
    let t0 = crate::profile::now_ns();
    if crate::compute::point(crate::state::thread(), frame, shown(pc), true) {
        count(proto::ctl::PLAN_POINTS);
    }
    frame.set_pc(pc + TRAP_LEN);
    crate::profile::record_plan_trap(crate::profile::now_ns().saturating_sub(t0));
    true
}

/// Before the program changes `[a, a + len)` (unmaps, maps over, moves, reprotects): the patched
/// pages of each image that the range touches, grown to whole patches, go back to the original
/// file's pages and leave the plan; all of them when it touches mapped trampolines (a page of
/// the trampolines' span that holds none is not the plan's). Nothing else is mapped: a page
/// that was not patched, or was already put back, is left as it is.
pub fn changing(a: u64, len: u64) {
    let lo = a & !(PAGE - 1);
    let hi = a.saturating_add(len).saturating_add(PAGE - 1) & !(PAGE - 1);
    for img in imgs().iter_mut() {
        let tramps = !img.tramp_gone
            && (0..img.w[R_NTRUNS]).any(|k| {
                let (off, n, _) = run_in(img, R_TRUNS, k);
                lo < img.tramp + off + n && img.tramp + off < hi
            });
        img.tramp_gone |= tramps;
        let (lo, hi) = if tramps { ALL } else { (lo, hi) };
        let mut touched = false;
        for_patched(img, &mut |s, e, _| touched |= s < hi && lo < e);
        if !touched {
            continue;
        }
        let (lo, hi) = if tramps { ALL } else { grown(img, lo, hi) };
        restore(img, lo, hi);
        let mut left = false;
        for_patched(img, &mut |_, _, _| left = true);
        count(if left {
            proto::ctl::PLAN_RESTORED
        } else {
            proto::ctl::PLAN_DROPPED
        });
    }
}

/// An interpreter turned its line points on (`python3 -m patina`: `compute::hello` with
/// `COMPUTE_LINE`): every plan of this process goes back to the original file, and no later
/// mapping in it takes one (a fork child keeps that; an exec starts again), so the cell counts
/// the interpreter's lines alone. A switch at a point inside the interpreter comes while the
/// thread holds the interpreter's lock, where no other thread can run its code, and the plans'
/// events would stretch the gap between line points. Counted `lines`, once per process whose
/// plans held patched text.
pub fn lines() {
    if !on() || proc().plans.lines {
        return;
    }
    proc().plans.lines = true;
    let mut any = false;
    for img in imgs().iter_mut() {
        let mut left = false;
        for_patched(img, &mut |_, _, _| left = true);
        if left {
            restore(img, ALL.0, ALL.1);
            any = true;
        }
    }
    if any {
        count(proto::ctl::PLAN_LINES);
    }
}

/// Code rebuilt with compute points said hello from `pc` (`compute::hello`, edges or
/// comparisons): the plan of the image holding `pc` goes back to the original file, so in that
/// image the cell counts the hooks' events alone, as without plans, instead of each place
/// counted twice (a hook call and a planned site beside it) and taken through a trampoline's
/// trap and walk half the time. Other images keep their plans; code of the image the compiler did
/// not instrument (a static libc, Rust's prebuilt `std`) loses its points with it. Counted
/// `rebuilt`, once per image load whose plan held patched text.
pub fn rebuilt(pc: u64) {
    // A vfork child runs on its parent's memory: the parent's plans are left as they are.
    if !on() || crate::state::thread().vfork != 0 {
        return;
    }
    let pc = shown(pc);
    for img in imgs().iter_mut() {
        if !img.maps[..img.nmaps]
            .iter()
            .any(|&(a, len, _)| a <= pc && pc - a < len)
        {
            continue;
        }
        let mut left = false;
        for_patched(img, &mut |_, _, _| left = true);
        if left {
            restore(img, ALL.0, ALL.1);
            count(proto::ctl::PLAN_REBUILT);
        }
    }
}

/// Map the original file's pages over the patched pages of `img` in `[lo, hi)` and mark the
/// range put back; past `MAX_RESTORED` ranges, every patched page.
fn restore(img: &mut Img, lo: u64, hi: u64) {
    let (prot, fd) = (img.prot, img.orig_fd as u64);
    let put = |img: &Img, lo: u64, hi: u64| {
        for_patched(img, &mut |s, e, off| {
            let (s2, e2) = (s.max(lo), e.min(hi));
            // (A plan is applied only to the program's own mappings, never in the runtime's
            // region; checked again before anything is mapped over.)
            if s2 >= e2 || (s2 < RT_REGION_END && e2 > RT_BASE) {
                return;
            }
            if !mmap(
                s2,
                e2 - s2,
                prot,
                MAP_PRIVATE | MAP_FIXED,
                fd,
                off + (s2 - s),
            ) {
                crate::sup::host_error(-e::ENOMEM, nr::MMAP, proto::ctl::HE_SYSCALL);
            }
            // The instruction channels' patches there (`rdrand`...) are written again.
            crate::insn::patch::rewrite(s2, e2 - s2, prot);
        });
    };
    put(img, lo, hi);
    if !mark(img, lo, hi) {
        put(img, ALL.0, ALL.1);
        img.restored[0] = ALL;
        img.nrestored = 1;
    }
}

/// Whether a mapping of `img` already holds `[a, a + len)` at file offset `off`.
fn covers(img: &Img, a: u64, len: u64, off: u64) -> bool {
    img.maps[..img.nmaps].iter().any(|&(ma, ml, mo)| {
        ma <= a && a + len <= ma + ml && mo.wrapping_sub(ma) == off.wrapping_sub(a)
    })
}

/// Whether `x` is in a range of `img` put back.
fn restored(img: &Img, x: u64) -> bool {
    img.restored[..img.nrestored]
        .iter()
        .any(|&(s, e)| s <= x && x < e)
}

/// The parts of `[s, e)` not put back, in order.
fn live(img: &Img, s: u64, e: u64, f: &mut dyn FnMut(u64, u64)) {
    let mut at = s;
    for &(rs, re) in &img.restored[..img.nrestored] {
        if at >= e {
            return;
        }
        if re <= at || rs >= e {
            continue;
        }
        if rs > at {
            f(at, rs);
        }
        at = at.max(re);
    }
    if at < e {
        f(at, e);
    }
}

/// The patched pages of `img` as mapped and still the plan's: start, end, and the original
/// file's offset there.
fn for_patched(img: &Img, f: &mut dyn FnMut(u64, u64, u64)) {
    for &(a, len, off) in &img.maps[..img.nmaps] {
        for k in 0..img.w[R_NRUNS] {
            let (va, n, _) = run(img, k);
            let (s, e) = (img.bias.wrapping_add(va), img.bias.wrapping_add(va + n));
            live(img, s.max(a), e.min(a + len), &mut |lo, hi| {
                f(lo, hi, off + (lo - a))
            });
        }
    }
}

/// The patched page piece holding `x`, if it is still the plan's.
fn patched_at(img: &Img, x: u64) -> Option<(u64, u64, u64)> {
    let mut at = None;
    for_patched(img, &mut |s, e, off| {
        if at.is_none() && s <= x && x < e {
            at = Some((s, e, off));
        }
    });
    at
}

/// Add `[lo, hi)` to the ranges put back, merged with those it meets; false, changing nothing,
/// when they would pass `MAX_RESTORED`.
fn mark(img: &mut Img, lo: u64, hi: u64) -> bool {
    let mut out = [(0u64, 0u64); MAX_RESTORED + 1];
    let (mut n, mut cur) = (0, Some((lo, hi)));
    for &(s, e) in &img.restored[..img.nrestored] {
        match cur {
            Some((l, h)) if e >= l && s <= h => cur = Some((l.min(s), h.max(e))),
            Some((l, h)) if s > h => {
                out[n] = (l, h);
                n += 1;
                cur = None;
                out[n] = (s, e);
                n += 1;
            }
            _ => {
                out[n] = (s, e);
                n += 1;
            }
        }
        if n > MAX_RESTORED {
            return false;
        }
    }
    if let Some(r) = cur {
        if n == MAX_RESTORED {
            return false;
        }
        out[n] = r;
        n += 1;
    }
    img.restored[..n].copy_from_slice(&out[..n]);
    img.nrestored = n;
    true
}

/// Take `[lo, hi)` out of the ranges put back (it is mapped afresh); false, changing nothing,
/// when the ranges left would pass `MAX_RESTORED`.
fn unrestore(img: &mut Img, lo: u64, hi: u64) -> bool {
    let mut out = [(0u64, 0u64); MAX_RESTORED];
    let mut n = 0;
    for &(s, e) in &img.restored[..img.nrestored] {
        for (s2, e2) in [(s, e.min(lo)), (s.max(hi), e)] {
            if s2 < e2 {
                if n == MAX_RESTORED {
                    return false;
                }
                out[n] = (s2, e2);
                n += 1;
            }
        }
    }
    img.restored[..n].copy_from_slice(&out[..n]);
    img.nrestored = n;
    true
}

/// Mappings of `img` whose patched pages were all put back hold nothing of the plan: forgotten,
/// so that a mapping again has room.
fn prune(img: &mut Img) {
    let mut k = 0;
    while k < img.nmaps {
        let mut one = *img;
        one.maps[0] = img.maps[k];
        one.nmaps = 1;
        let mut left = false;
        for_patched(&one, &mut |_, _, _| left = true);
        if left {
            k += 1;
        } else {
            img.maps.copy_within(k + 1..img.nmaps, k);
            img.nmaps -= 1;
        }
    }
}

/// The patches of `img` (sites, and `cpuid`s written in place) that cross the page boundary
/// `b`: the lowest start and the highest end among them, or none.
fn crossing(img: &Img, b: u64) -> Option<(u64, u64)> {
    let mut r: Option<(u64, u64)> = None;
    let mut see = |s: u64, n: u64| {
        if s < b && b < s + n {
            r = Some(r.map_or((s, s + n), |(lo, hi)| (lo.min(s), hi.max(s + n))));
        }
    };
    let sites = img.hdr + img.w[R_SITES];
    for k in 0..img.w[R_NSITES] {
        let row = sites + k * SITE_BYTES as u64;
        see(
            img.bias.wrapping_add(field::<u64>(row, SITE_ADDR)),
            field::<u8>(row, SITE_LEN) as u64,
        );
    }
    let entries = img.hdr + img.w[R_ENTRIES];
    for k in 0..img.w[R_NENTRIES] {
        let row = entries + k * ENTRY_BYTES as u64;
        if field::<u8>(row, ENTRY_KIND) == KIND_CPUID {
            see(img.bias.wrapping_add(field::<u64>(row, ENTRY_ADDR)), 2);
        }
    }
    r
}

/// `[lo, hi)` grown to whole patches: a patch that crosses its edge from a patched page on the
/// other side takes that page too, so no patch is ever half put back. On arm64 every patch is
/// one aligned word, and nothing grows.
fn grown(img: &Img, mut lo: u64, mut hi: u64) -> (u64, u64) {
    if cfg!(target_arch = "aarch64") {
        return (lo, hi);
    }
    let both = |b: u64| patched_at(img, b - 1).is_some() && patched_at(img, b).is_some();
    loop {
        let (l0, h0) = (lo, hi);
        if lo >= PAGE && both(lo) {
            if let Some((s, _)) = crossing(img, lo) {
                lo = s & !(PAGE - 1);
            }
        }
        if hi < u64::MAX - PAGE && both(hi) {
            if let Some((_, e)) = crossing(img, hi) {
                hi = (e + PAGE - 1) & !(PAGE - 1);
            }
        }
        if (lo, hi) == (l0, h0) {
            return (lo, hi);
        }
    }
}

/// `[lo, hi)` (what a new mapping covers) shrunk so that no patch crosses its edge into a page
/// that stays put back: such a page keeps its original code, and so must the patch's other page.
fn revived(img: &Img, mut lo: u64, mut hi: u64) -> (u64, u64) {
    if cfg!(target_arch = "aarch64") {
        return (lo, hi);
    }
    while lo < hi {
        let (l0, h0) = (lo, hi);
        if lo >= PAGE && restored(img, lo - 1) {
            if let Some((_, e)) = crossing(img, lo) {
                lo = (e + PAGE - 1) & !(PAGE - 1);
            }
        }
        if lo < hi && restored(img, hi) {
            if let Some((s, _)) = crossing(img, hi) {
                hi = s & !(PAGE - 1);
            }
        }
        if (lo, hi) == (l0, h0) {
            break;
        }
    }
    (lo, hi)
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
        let at = imgs()
            .iter()
            .filter(ours)
            .find_map(|m| patched_at(m, start).map(|p| (m, p)));
        // (arm64 trampolines before and after an image: its span holds the image)
        if at.is_none() && imgs().iter().filter(ours).any(|m| tramp(&m)) {
            return;
        }
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
