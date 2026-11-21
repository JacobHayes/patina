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
//!     `HWCAP2_RNG`) or the run asks for it (`PATINA_TEST_EMULATE_RNDR`, which also advertises it).
//!     On a host without it the site is left alone: executing it raises SIGILL, a host-stable
//!     fact, as it would outside Patina.
//!   - `yield`, `wfe`, `wfi`, `isb`: pause points (`Config::pause_points`). An `isb` that is not a
//!     spin hint (after a system-register write, ending a cache flush) loses nothing: the
//!     SIGILL entry and the return from it are context synchronization events themselves.
//!   - `pacga`: counted (`pacga_sites`), not patched.
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

/// At image start, from the kernel's `AT_HWCAP2`.
pub fn init(hwcap2: Option<u64>) {
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
    let mut search = |a: u64, n: u64| {
        let words = unsafe { core::slice::from_raw_parts(a as *const u32, (n / 4) as usize) };
        proto::insn::sites(words, a, |i, r| {
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
