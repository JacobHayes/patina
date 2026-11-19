//! arm64's instruction rule and emulators (`crate::insn` holds the portable part).
//!
//! - `tsc`: the counter-timer. `PR_SET_TSC(PR_TSC_SIGSEGV)` makes `mrs` of `CNTVCT_EL0`,
//!   `CNTVCTSS_EL0` and `CNTFRQ_EL0` fault wherever the code came from (Linux 6.12); the fault
//!   entry answers from virtual time. Complete. `CNTPCT_EL0` and `CNTPCTSS_EL0` are not
//!   readable at EL0 under Linux: SIGILL to the program, the same in every run.
//! - The scan (`scan_range`): the words of the executable sections of an executable file
//!   mapping, under `proto::insn`'s rule. A site is overwritten with `udf #0x7061`
//!   (`proto::insn::UDF`) and `emulate` answers the SIGILL:
//!   - `RNDR`/`RNDRRS`: a draw from the seed, when the host has the instruction (the kernel's
//!     `HWCAP2_RNG`) or the run asks for it (`[run] emulate-rndr`, which also advertises it).
//!     On a host without it the site is left alone: executing it raises SIGILL, a host-stable
//!     fact, as it would outside Patina.
//!   - `yield`, `wfe`, `wfi`, `isb`: pause points (`sched.pause-points`). An `isb` that is not a
//!     spin hint (after a system-register write, ending a cache flush) loses nothing: the
//!     SIGILL entry and the return from it are context synchronization events themselves.
//!   - `pacga`: counted (`pacga_sites`), not patched.
//!   - With counter preemption, the exclusive instructions (`exclusive`): emulated, so that a
//!     store-exclusive fails only when the program's own path makes it fail.
//!
//! BTI: no landing pad (`bti`, `paciasp`, `pacibsp`) is a candidate, so patching never removes
//! one, and `udf` is no more a landing pad than the instruction it replaced: an indirect branch
//! to a site in a guarded page faults (SIGILL) with or without the patch. That SIGILL is the
//! program's: a site whose saved `PSTATE.BTYPE` is not zero in a page mapped `PROT_BTI` is not
//! emulated.

use crate::insn::scan::{pread, FileId};
use crate::insn::{bump, REJECTED};
use crate::state::{config, ctl};
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};
use proto::insn::SiteKind;

/// The bytes written over a site: `udf #0x7061`.
pub const PATCH: &[u8] = &proto::insn::UDF.to_le_bytes();

/// `PROT_BTI`: the pages are guarded.
pub const PROT_BTI: u64 = 0x10;

/// After writing the word at `a`: clean it to the point of unification, invalidate the
/// instruction cache there, and synchronize, so that every core fetches the new word.
pub fn sync_code(a: u64, _len: u64) {
    unsafe {
        core::arch::asm!(
            "dc cvau, {a}",
            "dsb ish",
            "ic ivau, {a}",
            "dsb ish",
            "isb",
            a = in(reg) a,
            options(nostack, preserves_flags)
        );
    }
}

/// Whether the host has `RNDR` (the kernel's `HWCAP2_RNG`), from this image's start.
static HOST_RNG: AtomicBool = AtomicBool::new(false);

/// `AT_HWCAP2`'s `HWCAP2_RNG`.
pub const HWCAP2_RNG: u64 = 1 << 16;

/// Whether the host has FEAT_LSE2 (the kernel's `HWCAP_USCAT`), from this image's start: an
/// unaligned exclusive access then faults only when it crosses a 16-byte boundary.
static HOST_USCAT: AtomicBool = AtomicBool::new(false);

/// `AT_HWCAP`'s `HWCAP_USCAT`.
pub const HWCAP_USCAT: u64 = 1 << 25;

/// At image start, from the kernel's `AT_HWCAP` and `AT_HWCAP2`.
pub fn init(hwcap: Option<u64>, hwcap2: Option<u64>) {
    HOST_USCAT.store(hwcap.unwrap_or(0) & HWCAP_USCAT != 0, Relaxed);
    HOST_RNG.store(hwcap2.unwrap_or(0) & HWCAP2_RNG != 0, Relaxed);
}

/// The protection bits the kernel adds to an image's executable segments when it maps the
/// image itself (the interpreter, or a program without one): `PROT_BTI` where the host has
/// BTI and the image's property note (`feature_1_and` of its type) marks it BTI.
pub fn image_prot(feature_1_and: impl FnOnce(u32) -> u32) -> u64 {
    const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
    const FEATURE_1_BTI: u32 = 1;
    if super::host_bti() && feature_1_and(GNU_PROPERTY_AARCH64_FEATURE_1_AND) & FEATURE_1_BTI != 0 {
        PROT_BTI
    } else {
        0
    }
}

/// Whether `RNDR`/`RNDRRS` sites are patched and answered (and the program is told the
/// instruction exists).
pub fn rndr_on() -> bool {
    HOST_RNG.load(Relaxed) || config().insn & proto::ctl::INSN_EMULATE_RNDR != 0
}

/// Search the executable sections of `[va, va + len)` (mapped, readable; from `file` when
/// it is a file mapping) and patch the sites. Each verdict is applied (`apply`) as it is
/// made and then given to `note` (offset in the mapping, verdict code).
pub fn scan_range(
    va: u64,
    len: u64,
    file: Option<FileId>,
    writable: bool,
    prot: u64,
    note: &mut dyn FnMut(u64, u8),
) {
    let exclusive = config().pmu & proto::ctl::PMU_ON != 0;
    let mut search = |a: u64, n: u64| {
        let words = unsafe { core::slice::from_raw_parts(a as *const u32, (n / 4) as usize) };
        proto::insn::sites_with(words, a, exclusive, |i, r| {
            // Err: data in text (a literal load reads the word).
            let k = r.map_or(REJECTED, |k| k as u8);
            let off = a + 4 * i as u64 - va;
            apply(va, off, k, writable, prot);
            note(off, k);
        });
    };
    match file {
        Some(f) => exec_sections(f, len, |o, n| search(va + o, n)),
        None => search(va, len),
    }
}

/// The effect of the verdict `k` on the word at `va + off`: count a rejected word or a
/// `pacga`, or patch the site (unless its kind is off in this run).
pub fn apply(va: u64, off: u64, k: u8, writable: bool, prot: u64) {
    let c = ctl();
    let pause = config().sched & proto::ctl::SCHED_PAUSE_POINTS != 0;
    if k == REJECTED {
        return bump(&c.insn.rejected_sites, 1);
    }
    if k == SiteKind::Pacga as u8 {
        return bump(&c.insn.counted_sites, 1);
    }
    if (k == SiteKind::Pause as u8 && !pause)
        || ((k == SiteKind::Rndr as u8 || k == SiteKind::Rndrrs as u8) && !rndr_on())
    {
        return;
    }
    if crate::insn::patch::patch(va + off, k, writable, prot) {
        bump(&c.insn.patched[k as usize], 1);
    } else if k == SiteKind::Exclusive as u8 {
        // Under counters an exclusive access left native fails at random, and one half
        // of a pair native and the other emulated never succeeds: the run stops.
        crate::sup::capacity(
            proto::ctl::LIMIT_PATCH_SITES,
            crate::insn::patch::CAP as u64,
        );
    } else {
        bump(&c.insn.table_full, 1);
        bump(&c.insn.rejected_sites, 1);
    }
}

/// Call `each(offset, len)` for each part of the mapping (`len` bytes of the file from
/// `f.off`) that the file's section headers mark executable: the rest of an executable segment
/// (the ELF header, symbol and string tables, read-only data) is data, whose words can look
/// like an instruction. A file without section headers is searched whole.
fn exec_sections(f: FileId, len: u64, mut each: impl FnMut(u64, u64)) {
    const SHF_EXECINSTR: u64 = 4;
    const SHT_NOBITS: u32 = 8;
    let mut eh = [0u8; 64];
    let u16_at = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]) as u64;
    let u64_at = |b: &[u8], o: usize| {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[o..o + 8]);
        u64::from_le_bytes(w)
    };
    let whole = !pread(f.fd, &mut eh, 0) || eh[..5] != *b"\x7fELF\x02" || {
        let (shoff, shentsize, shnum) = (u64_at(&eh, 0x28), u16_at(&eh, 0x3a), u16_at(&eh, 0x3c));
        shoff == 0 || shnum == 0 || shentsize != 64
    };
    if whole {
        return each(0, len & !3);
    }
    let (shoff, shnum) = (u64_at(&eh, 0x28), u16_at(&eh, 0x3c));
    let (lo, hi) = (f.off, f.off + len);
    let mut sh = [0u8; 64];
    for i in 0..shnum {
        if !pread(f.fd, &mut sh, shoff + i * 64) {
            return each(0, len & !3);
        }
        let typ = u32::from_le_bytes([sh[4], sh[5], sh[6], sh[7]]);
        if u64_at(&sh, 8) & SHF_EXECINSTR == 0 || typ == SHT_NOBITS {
            continue;
        }
        let (s, e) = (
            u64_at(&sh, 0x18),
            u64_at(&sh, 0x18).saturating_add(u64_at(&sh, 0x20)),
        );
        let (s, e) = ((s.max(lo) + 3) & !3, e.min(hi) & !3);
        if s < e {
            each(s - lo, e - s);
        }
    }
}

pub mod emulate {
    use super::PROT_BTI;
    use crate::arch::Frame;
    use crate::entry::{charge, maybe_yield};
    use crate::state::{config, thread};
    use crate::sys::sig::{self, SigInfo};
    use proto::ctl::{INSN_RNDR, INSN_RNDRRS};
    use proto::insn::{SiteKind, UDF};
    use proto::{draw, Stream};

    const PSTATE_BTYPE: u64 = 3 << 10;
    const PSTATE_NZCV: u64 = 0xf << 28;

    /// The site of a SIGILL at a word the runtime patched. Any other SIGILL (the program's own
    /// `udf`, an instruction the host lacks) is not ours.
    fn site(frame: &Frame, sig: i32, info: &SigInfo) -> Option<crate::insn::patch::Entry> {
        // From the CPU (`ILL_ILLOPC`), not a SIGILL the program sent itself.
        if sig as u64 != sig::SIGILL || (info[1] & 0xffff_ffff) as i32 <= 0 {
            return None;
        }
        let pc = frame.pc();
        let site = crate::insn::patch::lookup(pc)?;
        // The program may have written its own code over the site since.
        if !matches!(crate::guest::get::<u32>(pc), Ok(UDF)) {
            return None;
        }
        // An indirect branch to a site in a guarded page: the branch-target fault, the
        // program's (the original instruction was not a landing pad either).
        if frame.pstate & PSTATE_BTYPE != 0 && site.prot as u64 & PROT_BTI != 0 {
            return None;
        }
        Some(site)
    }

    /// SIGILL at a word the runtime patched: emulate the original instruction.
    pub fn try_emulate(frame: &mut Frame, sig: i32, info: &SigInfo) -> bool {
        let pc = frame.pc();
        let Some(site) = site(frame, sig, info) else {
            return false;
        };
        // Moving past an instruction ends the branch it was the target of, as the kernel's own
        // skip does.
        frame.pstate &= !PSTATE_BTYPE;
        let orig = u32::from_le_bytes(site.orig);
        if site.kind == SiteKind::Pause as u8 {
            return crate::insn::pause_point(frame, pc, 4, orig);
        }
        if site.kind == SiteKind::Exclusive as u8 {
            if let Err(f) = super::exclusive::emulate(frame, pc, orig) {
                super::exclusive::raise(frame, f);
            }
            return true;
        }
        let (code, idx) = if site.kind == SiteKind::Rndr as u8 {
            (proto::insn::RNDR, INSN_RNDR)
        } else if site.kind == SiteKind::Rndrrs as u8 {
            (proto::insn::RNDRRS, INSN_RNDRRS)
        } else {
            return false;
        };
        let ts = thread();
        charge(ts);
        crate::insn::count_emulated(idx);
        let c = crate::state::ctl();
        crate::insn::bump(&c.stats.insn_emulations, 1);
        let v = draw(config().seed, Stream::Entropy, ts.seq);
        frame.set_xreg((orig & 0x1f) as usize, v);
        // NZCV = 0000: a value was returned.
        frame.pstate &= !PSTATE_NZCV;
        frame.set_pc(pc + 4);
        crate::log::insn(code, pc, v);
        maybe_yield(ts);
        true
    }
}

/// The exclusive instructions under counter preemption.
///
/// A store-exclusive natively fails now and then without another writer (an interrupt on the
/// host clears the monitor): the retry loop then runs again, two more branches counted, more
/// or less often by host and run. Emulated, the monitor is the thread's: a load-exclusive
/// records the address and size and the boundary-event sequence number (`Ctl::seq`); the
/// store succeeds when they all still match, and fails when anything that could let another
/// thread run came between (a trap, a preemption, a signal: each takes a sequence number),
/// the same way in every run. The guest threads run one at a time, so a plain load and store
/// are the atomic access. Emulation is not a boundary event (no record, no sequence number,
/// no yield): the hops' breakpoints and the overflow signal in between leave the monitor
/// alone. Its SIGILL still ends the counted segment, as every runtime entry does
/// (ARCHITECTURE.md, "arm64" under counter preemption). An access that would fault (unaligned,
/// unmapped, not readable or writable) raises the fault the instruction would (SIGBUS
/// `BUS_ADRALN`, SIGSEGV), with the program counter still at it: the site stays emulated, so a
/// handler that fixes the page and returns runs it again, and both halves of a pair stay on the
/// one monitor. Unaligned is the architecture's rule (`AArch64.CheckAlignment`): an address not
/// a multiple of the access's size (a pair's both elements) faults, except that with FEAT_LSE2
/// it faults only when the access crosses a 16-byte boundary; the store's alignment check comes
/// before its monitor's, so a store that would fail faults too.
pub mod exclusive {
    use crate::arch::Frame;
    use crate::raw::sc3;
    use crate::state::{ctl, thread};
    use crate::sys::sig;
    use core::sync::atomic::Ordering::Relaxed;
    use proto::nr;

    const BUS_ADRALN: i32 = 1;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;

    /// A fault the access raises: signal, `si_code`, address.
    pub struct Fault(u64, i32, u64);

    /// Deliver the fault as the CPU's would be: a boundary event, recorded, then the program's
    /// disposition (`force_sig`), with the program counter still at the instruction.
    pub fn raise(frame: &mut Frame, f: Fault) {
        let ts = thread();
        crate::entry::charge(ts);
        let mut info = sig::siginfo(f.0, f.1, 0, 0);
        info[2] = f.2;
        crate::log::fault(f.0, &info, frame.pc());
        sig::force(frame, ts, f.0, &info, false);
    }

    /// SEGV_ACCERR when a mapping holds `addr` (`mincore` succeeds on any mapped page),
    /// SEGV_MAPERR when none does.
    fn segv(addr: u64) -> Fault {
        let mut v = 0u8;
        let r = unsafe { sc3(nr::MINCORE, addr & !0xfff, 1, &mut v as *mut u8 as u64) };
        Fault(
            sig::SIGSEGV,
            if r == 0 { SEGV_ACCERR } else { SEGV_MAPERR },
            addr,
        )
    }

    const PSTATE_BTYPE: u64 = 3 << 10;

    /// Emulate the exclusive instruction `w` patched at `pc`. A fault changes nothing (the
    /// monitor included): emulating again raises it again.
    pub fn emulate(frame: &mut Frame, pc: u64, w: u32) -> Result<(), Fault> {
        let ts = thread();
        let m = &mut ts.pmu;
        frame.pstate &= !PSTATE_BTYPE;
        if w & 0xffff_f0ff == 0xd503_305f {
            // clrex
            m.excl_size = 0;
            frame.set_pc(pc + 4);
            return Ok(());
        }
        let (size, pair, load) = (w >> 30, w >> 21 & 1 == 1, w >> 22 & 1 == 1);
        let (rt, rt2, rn, rs) = (
            (w & 0x1f) as usize,
            (w >> 10 & 0x1f) as usize,
            (w >> 5 & 0x1f) as usize,
            (w >> 16 & 0x1f) as usize,
        );
        // Element and total size: a pair is two 32- or 64-bit elements.
        let esize: u64 = if pair { 4 << (size & 1) } else { 1 << size };
        let total = if pair { 2 * esize } else { esize };
        let addr = if rn == 31 { frame.sp() } else { frame.regs[rn] };
        let acq_rel = w >> 15 & 1 == 1;
        if addr % total != 0 && (!super::HOST_USCAT.load(Relaxed) || (addr & 15) + total > 16) {
            return Err(Fault(sig::SIGBUS, BUS_ADRALN, addr));
        }
        let reg = |f: &Frame, r: usize| if r == 31 { 0 } else { f.regs[r] };
        let seq = ctl().seq.load(Relaxed);
        if load {
            let mut b = [0u8; 16];
            if crate::guest::read(addr, &mut b[..total as usize]).is_err() {
                return Err(segv(addr));
            }
            if acq_rel {
                unsafe { core::arch::asm!("dmb ish", options(nostack, preserves_flags)) };
            }
            let lo = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            let hi = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
            let mask = if esize == 8 {
                u64::MAX
            } else {
                (1u64 << (8 * esize)) - 1
            };
            if pair && esize == 4 {
                frame.set_xreg(rt, lo & mask);
                frame.set_xreg(rt2, lo >> 32);
            } else if pair {
                frame.set_xreg(rt, lo);
                frame.set_xreg(rt2, hi);
            } else {
                frame.set_xreg(rt, lo & mask);
            }
            m.excl_addr = addr;
            m.excl_size = total;
            m.excl_seq = seq;
        } else {
            let ok = m.excl_size == total && m.excl_addr == addr && m.excl_seq == seq;
            if ok {
                let mut b = [0u8; 16];
                let (v, v2) = (reg(frame, rt), reg(frame, rt2));
                if pair && esize == 4 {
                    b[..4].copy_from_slice(&(v as u32).to_le_bytes());
                    b[4..8].copy_from_slice(&(v2 as u32).to_le_bytes());
                } else if pair {
                    b[..8].copy_from_slice(&v.to_le_bytes());
                    b[8..].copy_from_slice(&v2.to_le_bytes());
                } else {
                    b[..8].copy_from_slice(&v.to_le_bytes());
                }
                if acq_rel {
                    unsafe { core::arch::asm!("dmb ish", options(nostack, preserves_flags)) };
                }
                if crate::guest::write(addr, &b[..total as usize]).is_err() {
                    return Err(segv(addr));
                }
            }
            m.excl_size = 0;
            // The status register (a W register): 0 stored, 1 not.
            frame.set_xreg(rs, !ok as u64);
        }
        frame.set_pc(pc + 4);
        Ok(())
    }
}

pub mod tsc {
    use crate::arch::Frame;
    use crate::entry::{charge, maybe_yield};
    use crate::state::{ctl, thread};
    use crate::sys::sig::{self, SigInfo};
    use core::sync::atomic::Ordering::Relaxed;

    const SI_KERNEL: i32 = 0x80;

    /// `mrs Xt, <register>` with `Rt` cleared, for the three registers that fault.
    const MRS_CNTVCT: u32 = 0xd53b_e040;
    const MRS_CNTVCTSS: u32 = 0xd53b_e0c0;
    const MRS_CNTFRQ: u32 = 0xd53b_e000;

    /// The counter's nominal frequency: one tick per virtual nanosecond.
    pub const CNTFRQ: u64 = 1_000_000_000;

    /// The guest's own `PR_SET_TSC` mode (1 = enabled, 2 = SIGSEGV), per process: the real
    /// mode is always SIGSEGV. A guest that asked for SIGSEGV gets the fault, not a value.
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

    /// The counter-timer fault: SIGSEGV, `SI_KERNEL`, no fault address and no syndrome; the
    /// word at `pc` says which register was read (`mrs`, any `Rt`; the zero register discards
    /// the value). The answer goes to `Rt`, `pc` moves on, and the read is a boundary event
    /// with an `insn` record (code: the word with `Rt` cleared). Any other word is not ours.
    pub fn try_emulate(frame: &mut Frame, sig: i32, info: &SigInfo) -> bool {
        if VMODE.load(Relaxed) == 2 {
            return false;
        }
        if sig as u64 != sig::SIGSEGV || (info[1] & 0xffff_ffff) as i32 != SI_KERNEL {
            return false;
        }
        let pc = frame.pc();
        // Through the guest copy: a `pc` in the runtime's region (program code that jumped
        // there) is not emulated, and the fault entry's containment check sees it.
        let Ok(word) = crate::guest::get::<u32>(pc) else {
            return false;
        };
        let code = word & !0x1f;
        if code != MRS_CNTVCT && code != MRS_CNTVCTSS && code != MRS_CNTFRQ {
            return false;
        }
        let ts = thread();
        charge(ts);
        let c = ctl();
        crate::insn::bump(&c.stats.insn_emulations, 1);
        crate::insn::count_emulated(if code == MRS_CNTFRQ {
            proto::ctl::INSN_CNTFRQ
        } else {
            proto::ctl::INSN_CNTVCT
        });
        let v = if code == MRS_CNTFRQ {
            CNTFRQ
        } else {
            c.vclock_ns.load(Relaxed)
        };
        frame.set_xreg((word & 0x1f) as usize, v);
        frame.pstate &= !(3 << 10); // PSTATE.BTYPE, as the kernel's skip clears it
        frame.set_pc(pc + 4);
        crate::log::insn(code, pc, v);
        maybe_yield(ts);
        true
    }

    /// At runtime start: make sure the counter faults (the setting survives fork, not
    /// execve). Returns whether it had to be set.
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
            crate::fatal(proto::ctl::Setup::SetTsc, 0);
        }
        true
    }
}
