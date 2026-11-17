//! Guest signal frames on arm64: `deliver` builds the kernel's `rt_sigframe` on the stack the
//! program asked for and edits the trap frame so that returning from the trap enters the
//! handler; `sigreturn` is the emulation of the program's `rt_sigreturn`
//! (`arch/arm64/kernel/signal.c`: `get_sigframe`, `setup_sigframe`, `setup_return`,
//! `restore_sigframe`).
//!
//! Layout, from the frame `f` up (no red zone):
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 128 | `siginfo` |
//! | 128 | 4,560 | `ucontext`: `uc_stack` at 16, `uc_sigmask` at 40, `uc_mcontext` at 176 (`fault_address`, `regs[31]`, `sp`, `pc`, `pstate`, the context records at 464) |
//! | 4,688 | 16 | frame record: the interrupted `x29`, `x30` |
//!
//! `f + 4,688` is `round_down(sp - 16, 16)` of the interrupted stack pointer, or of the top of
//! the program's alternate stack for `SA_ONSTACK`.
//!
//! The context records are the trap frame's (the kernel's frame for the runtime's handler,
//! made at the same moment for the same thread), normalised so that they are a function of
//! the program's registers, not of the kernel's history:
//! - FPSIMD: copied. The handler starts with the interrupted FP/SIMD registers, as natively
//!   (the arm64 kernel does not reset them for a handler).
//! - ESR and `fault_address`: only for a synchronous fault whose syndrome the kernel has just
//!   recorded (an abort, an undefined or a breakpoint instruction), as the trap frame has
//!   them; otherwise absent and 0. The kernel keeps the thread's last fault code until the
//!   next one, which under Patina would expose the runtime's own faults (a guest copy
//!   answering `EFAULT`): the normalisation x86_64 makes for `trapno`, `err` and `cr2`.
//! - SVE (hosts with SVE or SME): the 16-byte header form whenever the state beyond FP/SIMD
//!   is zero (the upper bits of every Z register, every P register, FFR), whatever form the
//!   trap frame has; the full form otherwise. The kernel's form depends on whether it kept
//!   the thread's state in SVE form, which a system call or a context switch decides.
//! - TPIDR2 and the ZA header (hosts with SME): copied; they are register values. The handler
//!   is entered with TPIDR2 0, as the kernel enters it.
//! - Anything else (streaming mode, ZA or ZT0 in use, FPMR, POE, GCS, an extra-context
//!   record, an unknown magic) ends the run `unsupported`, stop `signal-context`.
//!
//! The handler's frame address does not depend on the records while they fit in the 4,096
//! bytes of `__reserved`, which every record above does for vector lengths up to 512 bits.

use super::{untagged, Frame, ESR_MAGIC};
use crate::raw::*;
use crate::state::ThreadState;
use crate::sys::sig::*;

/// `siginfo` and `ucontext`: the kernel's `sigframe_size` while the records fit.
const INFO_SIZE: u64 = 128;
const FRAME_SIZE: u64 = INFO_SIZE + core::mem::size_of::<Frame>() as u64;
/// The frame record above it.
const RECORD_SIZE: u64 = 16;

const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: usize = 528;
const SVE_MAGIC: u32 = 0x5356_4501;
const SVE_FLAG_SM: u16 = 1;
const TPIDR2_MAGIC: u32 = 0x5450_4902;
const TPIDR2_SIZE: usize = 16;
const ZA_MAGIC: u32 = 0x5436_6345;
const ZT_MAGIC: u32 = 0x5a54_4e01;
const EXTRA_MAGIC: u32 = 0x4558_5401;
/// The `sve_context` and `za_context` headers (magic, size, vector length, flags), and the
/// terminating record.
const HDR: usize = 16;

/// `SVE_SIG_CONTEXT_SIZE(vq)`: the header, 32 Z registers, 16 P registers and FFR.
fn sve_size(vq: usize) -> usize {
    if vq == 0 {
        HDR
    } else {
        HDR + 32 * 16 * vq + 17 * 2 * vq
    }
}

/// `ZA_SIG_CONTEXT_SIZE(vq)`.
fn za_size(vq: usize) -> usize {
    if vq == 0 {
        HDR
    } else {
        HDR + 256 * vq * vq
    }
}

/// `PSTATE` bits (`uapi/asm/ptrace.h`).
const PSR_BTYPE_MASK: u64 = 0xc00;
const PSR_BTYPE_C: u64 = 0x800;
const PSR_TCO: u64 = 1 << 25;
const PSR_SS: u64 = 1 << 21;
const PSR_DAIF: u64 = 0x3c0;
/// M[4:0]: an AArch64 EL0t state has them all 0.
const PSR_MODE: u64 = 0x1f;
const PSR_NZCV: u64 = 0xf000_0000;
/// `SPSR_EL1_AARCH64_RES0_BITS`: cleared from a frame's `pstate` (`valid_user_regs`).
const PSR_RES0: u64 = 0xffff_ffff_0000_0000 | 3 << 26 | 3 << 22 | 0xff << 13 | 1 << 5;

const SI_KERNEL: i32 = 0x80;
const TRAP_BRKPT: i32 = 1;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;
const SEGV_MTEAERR: i32 = 8;

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd64(b: &[u8], o: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(w)
}
fn header(out: &mut [u8], magic: u32, size: usize, vl: u16) {
    out[..HDR].fill(0);
    out[0..4].copy_from_slice(&magic.to_le_bytes());
    out[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    out[8..10].copy_from_slice(&vl.to_le_bytes());
}

/// One context record: magic, offset in `__reserved`, size.
#[derive(Clone, Copy, Default)]
struct Rec {
    magic: u32,
    off: usize,
    size: usize,
}

/// The record list of a `__reserved` area, with the structure checks of the kernel's
/// `parse_user_sigframe` (16-byte aligned records, sizes inside the area, a zero terminator).
/// ESR records are left out (`rt_sigreturn` ignores them) unless `esr`.
fn parse(b: &[u8; 4096], esr: bool, out: &mut [Rec; 16]) -> Result<usize, ()> {
    let (mut off, mut n) = (0usize, 0usize);
    loop {
        if b.len() - off < 8 || off % 16 != 0 {
            return Err(());
        }
        let (magic, size) = (rd32(b, off), rd32(b, off + 4) as usize);
        if b.len() - off < size {
            return Err(());
        }
        if magic == 0 {
            return if size == 0 { Ok(n) } else { Err(()) };
        }
        if size < 8 {
            return Err(());
        }
        if magic != ESR_MAGIC || esr {
            if n == out.len() {
                return Err(());
            }
            out[n] = Rec { magic, off, size };
            n += 1;
        }
        off += size;
    }
}

/// The trap frame's records (made by the kernel: a malformed list is a runtime defect).
fn trap_records(t: &[u8; 4096], out: &mut [Rec; 16]) -> usize {
    match parse(t, true, out) {
        Ok(n) => n,
        Err(()) => crate::sup::host_error(0, 0, proto::ctl::HE_RUNTIME_ASSERT),
    }
}

/// What the host's frames hold beyond FP/SIMD, from the trap frame: the SVE record's vector
/// length (hosts with SVE or SME), TPIDR2's value and the ZA record's vector length (SME).
/// State the runtime does not build ends the run.
#[derive(Default)]
struct Host {
    sve_vl: Option<u16>,
    tpidr2: Option<u64>,
    za_vl: Option<u16>,
}

fn host(t: &[u8; 4096]) -> Host {
    let mut recs = [Rec::default(); 16];
    let n = trap_records(t, &mut recs);
    let mut h = Host::default();
    for r in &recs[..n] {
        let src = &t[r.off..r.off + r.size];
        match r.magic {
            FPSIMD_MAGIC | ESR_MAGIC => {}
            SVE_MAGIC if r.size >= HDR => {
                if rd16(src, 10) & SVE_FLAG_SM != 0 {
                    crate::sup::signal_context(SVE_MAGIC);
                }
                h.sve_vl = Some(rd16(src, 8));
            }
            TPIDR2_MAGIC if r.size == TPIDR2_SIZE => h.tpidr2 = Some(rd64(src, 8)),
            ZA_MAGIC if r.size == HDR => h.za_vl = Some(rd16(src, 8)),
            m => crate::sup::signal_context(m),
        }
    }
    h
}

/// Is any of the SVE state beyond FP/SIMD non-zero in this full `sve_context`: the upper bits
/// of a Z register, a P register, FFR?
fn sve_beyond_fpsimd(src: &[u8], vq: usize) -> bool {
    let z = |i: usize| HDR + i * 16 * vq;
    (0..32).any(|i| src[z(i) + 16..z(i) + 16 * vq].iter().any(|&b| b != 0))
        || src[z(32)..sve_size(vq)].iter().any(|&b| b != 0)
}

/// The program's records from the trap frame's (the rules in the module comment). `syndrome`:
/// keep the ESR record.
fn program_records(t: &[u8; 4096], syndrome: bool) -> [u8; 4096] {
    let mut out = [0u8; 4096];
    let mut recs = [Rec::default(); 16];
    let n = trap_records(t, &mut recs);
    let mut w = 0usize;
    for r in &recs[..n] {
        let src = &t[r.off..r.off + r.size];
        let size = match r.magic {
            FPSIMD_MAGIC | TPIDR2_MAGIC => r.size,
            ESR_MAGIC if syndrome => r.size,
            ESR_MAGIC => continue,
            SVE_MAGIC if r.size >= HDR => {
                let (vl, flags) = (rd16(src, 8), rd16(src, 10));
                let vq = vl as usize / 16;
                if flags & SVE_FLAG_SM != 0 {
                    crate::sup::signal_context(SVE_MAGIC);
                }
                if r.size > HDR && r.size < sve_size(vq) {
                    crate::sup::host_error(0, 0, proto::ctl::HE_RUNTIME_ASSERT);
                }
                if r.size == HDR || !sve_beyond_fpsimd(src, vq) {
                    header(&mut out[w..], SVE_MAGIC, HDR, vl);
                    w += HDR;
                    continue;
                }
                r.size
            }
            ZA_MAGIC if r.size == HDR => r.size,
            m => crate::sup::signal_context(m),
        };
        out[w..w + size].copy_from_slice(src);
        if r.magic == SVE_MAGIC {
            // The kernel fills `SVE_SIG_CONTEXT_SIZE` and leaves the rounding up to 16 bytes
            // as whatever its stack held.
            let vq = rd16(src, 8) as usize / 16;
            out[w + sve_size(vq)..w + size].fill(0);
        }
        w += size;
    }
    out
}

/// Does a fault signal's `si_addr` carry the address (the kernel's `SIL_FAULT` layouts):
/// SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP with a code of their own?
fn fault_layout(sig: u64, code: i32) -> bool {
    let limit = match sig {
        SIGILL => 11,
        SIGFPE => 15,
        SIGSEGV => 10,
        SIGBUS => 5,
        SIGTRAP => 6,
        _ => return false,
    };
    code > 0 && code <= limit
}

/// The frame as written to the program's stack.
#[repr(C, align(16))]
struct Sigframe {
    info: SigInfo,
    uc: Frame,
    fp: u64,
    lr: u64,
}
const _: () = assert!(core::mem::size_of::<Sigframe>() as u64 == FRAME_SIZE + RECORD_SIZE);

/// Build a frame for `sig` with handler `act` and edit the trap frame to enter it. `fault`:
/// a synchronous fault from the fault entry.
pub fn deliver(
    frame: &mut Frame,
    ts: &mut ThreadState,
    sig: u64,
    info: &SigInfo,
    act: [u64; 4],
    fault: bool,
) {
    let [handler, flags, restorer, sa_mask] = act;
    let mask = if ts.has_saved != 0 {
        ts.saved_mask
    } else {
        ts.vmask
    };
    let valt = ts.valt;
    let sp0 = frame.sp;
    // `sigsp`: the arm64 kernel has no "overflowed alternate stack" check of its own; a
    // frame that does not fit fails to be written like any other.
    let top = if flags & SA_ONSTACK != 0 && sas_ss_flags(&valt, sp0) == 0 {
        valt[0].wrapping_add(valt[2])
    } else {
        sp0
    };
    let fr = top.wrapping_sub(RECORD_SIZE) & !15;
    let f = fr.wrapping_sub(FRAME_SIZE);
    let code = info[1] as u32 as i32;
    // The kernel recorded a syndrome for this fault (aborts, undefined and breakpoint
    // instructions), not for the counter-timer trap (`SI_KERNEL`), an FP exception, a
    // hardware breakpoint or single step, or an asynchronous tag-check fault.
    let syndrome = fault
        && sig != SIGFPE
        && code != SI_KERNEL
        && !(sig == SIGTRAP && code != TRAP_BRKPT)
        && !(sig == SIGSEGV && code == SEGV_MTEAERR);
    let mut si = *info;
    if flags & SA_EXPOSE_TAGBITS == 0
        && fault_layout(sig, code)
        && !(sig == SIGTRAP && code == TRAP_BRKPT)
    {
        si[2] = untagged(si[2]);
    }
    let mut sf = Sigframe {
        info: if flags & SA_SIGINFO != 0 { si } else { [0; 16] },
        uc: *frame,
        fp: frame.regs[29],
        lr: frame.regs[30],
    };
    let uc = &mut sf.uc;
    uc.uc_flags = 0;
    uc.uc_link = 0;
    uc.ss_sp = valt[0];
    uc.ss_flags = valt[1] as u32;
    uc._pad = 0;
    uc.ss_size = valt[2];
    uc.sigmask = mask;
    uc._unused = [0; 15];
    uc._align = 0;
    uc.fault_address = if syndrome { frame.fault_address } else { 0 };
    uc._pad2 = 0;
    uc.records = program_records(&frame.records, syndrome);
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &sf as *const Sigframe as *const u8,
            core::mem::size_of::<Sigframe>(),
        )
    };
    if crate::guest::write(f, bytes).is_err() {
        // `force_sigsegv`: the frame could not be written.
        if sig == SIGSEGV {
            die(SIGSEGV);
        }
        force(
            frame,
            ts,
            SIGSEGV,
            &siginfo(SIGSEGV, SI_KERNEL, 0, 0),
            false,
        );
        return;
    }
    charge_delivery(sig, handler, f, &si, frame.pc, frame.sp);
    frame.regs[0] = sig;
    if flags & SA_SIGINFO != 0 {
        frame.regs[1] = f;
        frame.regs[2] = f + INFO_SIZE;
    }
    frame.sp = f;
    frame.regs[29] = fr;
    frame.regs[30] = if flags & SA_RESTORER != 0 {
        restorer
    } else {
        default_restorer()
    };
    frame.pc = handler;
    // Entry is an indirect call (`blr`): on a host with BTI, a handler in guarded code must
    // start with a landing pad, as natively. The kernel takes `BTYPE` from the trap frame
    // when the runtime's handler returns.
    if super::host_bti() {
        frame.pstate = frame.pstate & !PSR_BTYPE_MASK | PSR_BTYPE_C;
    }
    frame.pstate &= !PSR_TCO;
    // SME hosts: the handler starts with TPIDR2 0 (streaming mode and ZA are off already:
    // `program_records` stops on them).
    let mut recs = [Rec::default(); 16];
    let n = trap_records(&frame.records, &mut recs);
    if let Some(r) = recs[..n].iter().find(|r| r.magic == TPIDR2_MAGIC) {
        frame.records[r.off + 8..r.off + 16].fill(0);
    }
    let mut m = mask | sa_mask;
    if flags & SA_NODEFER == 0 {
        m |= bit(sig);
    }
    ts.has_saved = 0;
    set_vmask(ts, m);
    if ts.valt[1] & SS_AUTODISARM != 0 {
        ts.valt = [0, SS_DISABLE, 0];
    }
    if flags & SA_RESETHAND != 0 {
        set_action(sig, [SIG_DFL, flags & !SA_SIGINFO, restorer, sa_mask]);
    }
}

/// Emulated `rt_sigreturn`: the frame is at the program's stack pointer. Registers, mask,
/// FP/SIMD and SVE state and the alternate stack come from its `ucontext`, including any
/// change the handler made. A frame the kernel would refuse gives the program SIGSEGV, as
/// natively; the runtime never reads it except through the guest copy. Returns the restored
/// `x0`.
pub fn sigreturn(frame: &mut Frame, ts: &mut ThreadState) -> i64 {
    // A restart block a handler left is never continued after a return from it.
    ts.restart = [RB_NONE, 0, 0, 0, 0];
    if restore(frame, ts).is_err() {
        // The call returns 0, then `arm64_notify_segfault(sp)`: SEGV_ACCERR unless no mapping
        // ends above the (untagged) address; the program's stack is the highest.
        frame.regs[0] = 0;
        let sp = frame.sp;
        let code = if untagged(sp) < proto::layout::STACK_TOP {
            SEGV_ACCERR
        } else {
            SEGV_MAPERR
        };
        let mut info = siginfo(SIGSEGV, code, 0, 0);
        info[2] = sp;
        force(frame, ts, SIGSEGV, &info, false);
    }
    frame.regs[0] as i64
}

/// `restore_sigframe` and `restore_altstack`: Err for a frame the kernel refuses. The trap
/// frame's FP/SIMD state is changed only for an accepted frame; registers and mask may be
/// changed before a refusal, as the kernel changes them.
fn restore(frame: &mut Frame, ts: &mut ThreadState) -> Result<(), ()> {
    let sp = frame.sp;
    if sp & 15 != 0 {
        return Err(());
    }
    // The guest copy may read the thread's own runtime stack (for the runtime's own buffers);
    // a frame there is not the program's: it reads as unmapped.
    let end = sp.wrapping_add(INFO_SIZE + core::mem::size_of::<Frame>() as u64);
    let in_rt = sp < proto::layout::RT_REGION_END && end > proto::layout::RT_BASE;
    let read = if in_rt {
        Err(())
    } else {
        crate::guest::get::<Frame>(sp.wrapping_add(INFO_SIZE)).map_err(|_| ())
    };
    let Ok(g) = read else {
        // The kernel's reads of the registers fail and store 0 (`__get_user_error`).
        frame.regs = [0; 31];
        frame.sp = 0;
        frame.pc = 0;
        frame.pstate = 0;
        return Err(());
    };
    set_vmask(ts, g.sigmask);
    frame.regs = g.regs;
    frame.sp = g.sp;
    frame.pc = g.pc;
    // `valid_user_regs`: reserved bits cleared, single-step off; anything but an AArch64 EL0t
    // state with the interrupt masks clear is refused (and left as NZCV only).
    let p = g.pstate & !PSR_RES0 & !PSR_SS;
    if p & PSR_MODE != 0 || p & PSR_DAIF != 0 {
        frame.pstate = p & PSR_NZCV;
        return Err(());
    }
    frame.pstate = p;
    frame.records = records_in(&g.records, &frame.records)?;
    // `restore_altstack`: errors other than a fault are ignored.
    let _ = set_altstack(ts, [g.ss_sp, g.ss_flags as u64, g.ss_size], frame.sp);
    Ok(())
}

/// The trap frame's new records from the program's frame `g` (validated as the kernel's
/// `parse_user_sigframe` and the `restore_*_context` functions do) and the trap frame's own
/// `t` (what the host has): the kernel loads them when the runtime's handler returns.
fn records_in(g: &[u8; 4096], t: &[u8; 4096]) -> Result<[u8; 4096], ()> {
    let h = host(t);
    let mut recs = [Rec::default(); 16];
    let n = parse(g, false, &mut recs)?;
    let (mut fp, mut sve, mut tp, mut za) = (None, None, None, None);
    for r in &recs[..n] {
        let slot = match r.magic {
            FPSIMD_MAGIC => &mut fp,
            SVE_MAGIC if h.sve_vl.is_some() => &mut sve,
            TPIDR2_MAGIC if h.tpidr2.is_some() => &mut tp,
            ZA_MAGIC if h.za_vl.is_some() => &mut za,
            // Valid on an SME2 or any host: state the runtime does not build.
            ZT_MAGIC if h.za_vl.is_some() => crate::sup::signal_context(ZT_MAGIC),
            EXTRA_MAGIC => crate::sup::signal_context(EXTRA_MAGIC),
            // Not a record of this host's (FPMR, POE, GCS exist on none that runs here: their
            // records would have stopped the run at its first delivery), or unknown.
            _ => return Err(()),
        };
        if slot.is_some() {
            return Err(());
        }
        *slot = Some(*r);
    }
    let fp = fp.ok_or(())?;
    if fp.size != FPSIMD_SIZE {
        return Err(());
    }
    let mut out = [0u8; 4096];
    out[..FPSIMD_SIZE].copy_from_slice(&g[fp.off..fp.off + FPSIMD_SIZE]);
    let mut w = FPSIMD_SIZE;
    if let Some(vl) = h.sve_vl {
        // Without an SVE record the kernel restores FP/SIMD only: the header form.
        let mut full = None;
        if let Some(r) = sve {
            if r.size < HDR {
                return Err(());
            }
            let (uvl, flags) = (rd16(g, r.off + 8), rd16(g, r.off + 10));
            if flags & SVE_FLAG_SM != 0 {
                let vq = h.za_vl.ok_or(())? as usize / 16;
                if Some(uvl) != h.za_vl || r.size < sve_size(vq) {
                    return Err(());
                }
                crate::sup::signal_context(SVE_MAGIC);
            }
            if uvl != vl {
                return Err(());
            }
            let vq = vl as usize / 16;
            if r.size > HDR && vq > 0 {
                if r.size < sve_size(vq) {
                    return Err(());
                }
                // With TPIDR2, ZA and the terminator after it, more than `__reserved` holds
                // (vector lengths above 512 bits): the kernel's extra-context form.
                if FPSIMD_SIZE + sve_size(vq) + 3 * HDR > g.len() {
                    crate::sup::signal_context(EXTRA_MAGIC);
                }
                full = Some((r.off, sve_size(vq)));
            }
        }
        match full {
            Some((off, size)) => {
                out[w..w + size].copy_from_slice(&g[off..off + size]);
                let padded = (size + 15) & !15;
                header(&mut out[w..], SVE_MAGIC, padded, vl);
                w += padded;
            }
            None => {
                header(&mut out[w..], SVE_MAGIC, HDR, vl);
                w += HDR;
            }
        }
    }
    if let Some(v) = h.tpidr2 {
        let v = match tp {
            Some(r) if r.size != TPIDR2_SIZE => return Err(()),
            Some(r) => rd64(g, r.off + 8),
            None => v,
        };
        header(&mut out[w..], TPIDR2_MAGIC, TPIDR2_SIZE, 0);
        out[w + 8..w + 16].copy_from_slice(&v.to_le_bytes());
        w += TPIDR2_SIZE;
    }
    if let Some(vl) = h.za_vl {
        if let Some(r) = za {
            if r.size < HDR || rd16(g, r.off + 8) != vl {
                return Err(());
            }
            if r.size > HDR {
                if r.size < za_size(vl as usize / 16) {
                    return Err(());
                }
                crate::sup::signal_context(ZA_MAGIC);
            }
        }
        header(&mut out[w..], ZA_MAGIC, HDR, vl);
    }
    Ok(out)
}

/// The restorer of handlers installed without `SA_RESTORER`: the restorer page.
pub fn default_restorer() -> u64 {
    proto::layout::SIGRETURN_PAGE
}

/// Map the restorer page: `mov x8, #139; svc #0` (`rt_sigreturn`), the kernel's own vDSO
/// trampoline, which unwinders match to recognise a signal frame.
pub fn map_restorer() {
    const MOV_X8_139: u32 = 0xd280_1168;
    const SVC_0: u32 = 0xd400_0001;
    const _: () = assert!(MOV_X8_139 == 0xd280_0008 | (crate::raw::nr::RT_SIGRETURN as u32) << 5);
    let page = proto::layout::SIGRETURN_PAGE;
    unsafe {
        let r = sc6(
            nr::MMAP,
            page,
            proto::layout::PAGE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            u64::MAX,
            0,
        );
        if r as u64 != page {
            crate::fatal(proto::ctl::Setup::RestorerPage, r);
        }
        core::ptr::write_volatile(page as *mut u32, MOV_X8_139);
        core::ptr::write_volatile((page + 4) as *mut u32, SVC_0);
        // Make the words visible to instruction fetch before the page becomes executable.
        core::arch::asm!(
            "dc cvau, {p}",
            "dsb ish",
            "ic ivau, {p}",
            "dsb ish",
            "isb",
            p = in(reg) page,
        );
        let r = sc3(
            nr::MPROTECT,
            page,
            proto::layout::PAGE,
            PROT_READ | PROT_EXEC,
        );
        if r != 0 {
            crate::fatal(proto::ctl::Setup::RestorerPage, r);
        }
    }
}
