//! Instruction channels on arm64, as far as the first slice of the port goes.
//!
//! - `tsc`: the counter-timer. `PR_SET_TSC(PR_TSC_SIGSEGV)` makes `mrs` of `CNTVCT_EL0`,
//!   `CNTVCTSS_EL0` and `CNTFRQ_EL0` fault wherever the code came from (Linux 6.12); the fault
//!   entry answers from virtual time. Complete.
//! - `scan`: a stand-in. The executable sections of executable file mappings are searched for
//!   `RNDR`/`RNDRRS` and `PACGA` (no trap exists for them) and a run that has one ends
//!   `arm64-unported`; nothing is patched, so the pause points (`yield`, `isb`, `wfe`) are not
//!   scheduling points yet. Words in an executable segment but outside every executable
//!   section (data, or code whose section headers misdescribe it) are not searched.
//!   Anonymous, shared and execute-only mappings, and ranges made executable later, end the
//!   run `arm64-unported` too.
//! - `emulate`, `patch`: nothing is patched, so nothing is emulated.

use crate::state::ctl;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Add to a counter (only the thread holding the turn writes).
pub fn bump(c: &AtomicU64, n: u64) {
    c.store(c.load(Relaxed) + n, Relaxed);
}

pub fn count_emulated(i: usize) {
    bump(&ctl().insn.emulated[i], 1);
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
    /// word at `pc` says which register was read. The answer goes to `Rt`, `pc` moves on, and
    /// the read is a boundary event with an `insn` record (code: the word with `Rt` cleared).
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
        super::count_emulated(if code == MRS_CNTFRQ {
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

pub mod scan {
    use super::bump;
    use crate::raw::*;
    use crate::state::ctl;

    /// `RNDR Xt` and `RNDRRS Xt` (`mrs Xt, RNDR` / `RNDRRS`) under this mask.
    const RNDR_MASK: u32 = 0xffff_ffc0;
    const RNDR: u32 = 0xd53b_2400;
    /// `PACGA Xd, Xn, Xm`: the generic key cannot be disabled (`arch::process_init`).
    const PACGA_MASK: u32 = 0xffe0_fc00;
    const PACGA: u32 = 0x9ac0_3000;

    /// The file a mapping came from: descriptor and file offset of the mapping's first byte.
    #[derive(Clone, Copy)]
    pub struct FileId {
        pub fd: u64,
        pub off: u64,
    }

    /// Search `[va, va + len)` (mapped, readable, backed by the file) for `RNDR`, `RNDRRS` and
    /// `PACGA`.
    pub fn scan_exec(va: u64, len: u64, file: Option<FileId>, _writable: bool, _prot: u64) {
        let c = ctl();
        // Pages wholly past the end of the file would raise SIGBUS when read.
        let len = match file {
            Some(f) => {
                // fstat, not lseek: the descriptor is the program's, and so is its offset.
                let Some(st) = crate::sys::fs::fstat_raw(f.fd as i64) else {
                    return;
                };
                len.min((st.size().saturating_sub(f.off) + 4095) & !4095)
            }
            None => len,
        };
        if len == 0 {
            return;
        }
        bump(&c.insn.scanned_mappings, 1);
        bump(&c.insn.scanned_bytes, len);
        let search = |a: u64, n: u64| {
            let words = unsafe { core::slice::from_raw_parts(a as *const u32, (n / 4) as usize) };
            if words
                .iter()
                .any(|&w| w & RNDR_MASK == RNDR || w & PACGA_MASK == PACGA)
            {
                crate::sup::unported(proto::ctl::UNPORTED_INSN);
            }
        };
        match file {
            Some(f) => exec_sections(f, len, |o, n| search(va + o, n)),
            None => search(va, len),
        }
    }

    /// Call `f(offset, len)` for each part of the mapping (`len` bytes of the file from `f.off`)
    /// that the file's section headers mark executable: the rest of an executable segment (the
    /// ELF header, symbol and string tables, read-only data) is data, whose words can look like
    /// an instruction. A file without section headers is searched whole.
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
            let (shoff, shentsize, shnum) =
                (u64_at(&eh, 0x28), u16_at(&eh, 0x3a), u16_at(&eh, 0x3c));
            shoff == 0 || shnum == 0 || shentsize != 64
        };
        if whole {
            return each(0, len);
        }
        let (shoff, shnum) = (u64_at(&eh, 0x28), u16_at(&eh, 0x3c));
        let (lo, hi) = (f.off, f.off + len);
        let mut sh = [0u8; 64];
        for i in 0..shnum {
            if !pread(f.fd, &mut sh, shoff + i * 64) {
                return each(0, len);
            }
            let typ = u32::from_le_bytes([sh[4], sh[5], sh[6], sh[7]]);
            if u64_at(&sh, 8) & SHF_EXECINSTR == 0 || typ == SHT_NOBITS {
                continue;
            }
            let (s, e) = (
                u64_at(&sh, 0x18),
                u64_at(&sh, 0x18).saturating_add(u64_at(&sh, 0x20)),
            );
            let (s, e) = ((s.max(lo) + 3) & !3, e.min(hi));
            if s < e {
                each(s - lo, e - s);
            }
        }
    }

    fn pread(fd: u64, buf: &mut [u8], off: u64) -> bool {
        let r = unsafe {
            sc4(
                nr::PREAD64,
                fd,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                off,
            )
        };
        r == buf.len() as i64
    }

    /// `mmap` succeeded at `[a, a + len)` with `prot`/`flags` on `fd` at `off`: a private,
    /// readable, executable file mapping is searched; any other executable mapping ends the run.
    pub fn on_mmap(a: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) {
        if prot & PROT_EXEC == 0 {
            return;
        }
        if flags & (MAP_ANONYMOUS | MAP_SHARED) != 0 || prot & PROT_READ == 0 {
            crate::sup::unported(proto::ctl::UNPORTED_UNSCANNED);
        }
        scan_exec(a, len, Some(FileId { fd, off }), false, prot);
    }

    /// `mprotect` made `[a, a + len)` executable: the run ends.
    pub fn on_mprotect_exec(_a: u64, _len: u64, _prot: u64) {
        crate::sup::unported(proto::ctl::UNPORTED_UNSCANNED);
    }
}

pub mod emulate {
    use crate::arch::Frame;
    use crate::sys::sig::SigInfo;

    /// Nothing is patched on arm64 yet: no SIGILL is a patched site's.
    pub fn try_emulate(_frame: &mut Frame, _sig: i32, _info: &SigInfo) -> bool {
        false
    }
}

pub mod patch {
    /// Nothing is patched on arm64 yet: no side table to update.
    pub fn forget(_a: u64, _len: u64) {}
    pub fn relocate(_old: u64, _len: u64, _new: u64) {}
}
