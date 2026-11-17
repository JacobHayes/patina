//! Instruction channels on arm64, as far as the first slice of the port goes.
//!
//! - `tsc`: the counter-timer. `PR_SET_TSC(PR_TSC_SIGSEGV)` makes `mrs` of `CNTVCT_EL0`,
//!   `CNTVCTSS_EL0` and `CNTFRQ_EL0` fault wherever the code came from (Linux 6.12); the fault
//!   entry answers from virtual time. Complete.
//! - `scan`: a stand-in. Executable file mappings are searched for `RNDR`/`RNDRRS` and `PACGA`
//!   (no trap exists for them) and a run that has one ends `arm64-unported`; nothing is
//!   patched, so the pause points (`yield`, `isb`, `wfe`) are not scheduling points yet.
//!   Anonymous, shared and execute-only mappings, and ranges made executable later, end the
//!   run `arm64-unported` too.
//! - `emulate`, `patch`: nothing is patched, so nothing is emulated.

use crate::state::ctl;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Add to a counter (only the thread holding the turn writes).
pub fn bump(c: &AtomicU64, n: u64) {
    c.store(c.load(Relaxed) + n, Relaxed);
}

#[allow(dead_code)]
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
        let word = unsafe { core::ptr::read_volatile(pc as *const u32) };
        let code = word & !0x1f;
        if code != MRS_CNTVCT && code != MRS_CNTVCTSS && code != MRS_CNTFRQ {
            return false;
        }
        let ts = thread();
        charge(ts);
        let c = ctl();
        crate::insn::bump(&c.stats.insn_emulations, 1);
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
                const SEEK_END: u64 = 2;
                let size = unsafe { sc3(nr::LSEEK, f.fd, 0, SEEK_END) };
                if size < 0 {
                    return;
                }
                len.min(((size as u64).saturating_sub(f.off) + 4095) & !4095)
            }
            None => len,
        };
        if len == 0 {
            return;
        }
        bump(&c.insn.scanned_mappings, 1);
        bump(&c.insn.scanned_bytes, len);
        let words = unsafe { core::slice::from_raw_parts(va as *const u32, (len / 4) as usize) };
        if words
            .iter()
            .any(|&w| w & RNDR_MASK == RNDR || w & PACGA_MASK == PACGA)
        {
            crate::sup::unported(proto::ctl::UNPORTED_INSN);
        }
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
