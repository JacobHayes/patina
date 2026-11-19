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
//! the program's registers, not of the kernel's history (`proto::sigrec`, which says what is
//! built for each record). ESR and `fault_address` are kept only for a synchronous fault whose
//! syndrome the kernel has just recorded (an abort, an undefined or a breakpoint instruction);
//! otherwise absent and 0. The kernel keeps the thread's last fault code until the next one,
//! which under Patina would expose the runtime's own faults (a guest copy answering `EFAULT`):
//! the normalisation x86_64 makes for `trapno`, `err` and `cr2`. Records the runtime does not
//! build end the run `unsupported`, stop `signal-context`.
//!
//! The handler's frame address does not depend on the records while they fit in the 4,096
//! bytes of `__reserved`, which every record built does for vector lengths up to 512 bits.

use super::{untagged, Frame};
use crate::raw::*;
use crate::state::ThreadState;
use crate::sys::sig::*;
use proto::sigrec::{self, Bad};

/// `siginfo` and `ucontext`: the kernel's `sigframe_size` while the records fit.
const INFO_SIZE: u64 = 128;
const FRAME_SIZE: u64 = INFO_SIZE + core::mem::size_of::<Frame>() as u64;
/// The frame record above it.
const RECORD_SIZE: u64 = 16;

/// A record list the runtime cannot go on with: a stop, or a runtime defect.
fn stop(b: Bad) -> ! {
    match b {
        Bad::Stop(m) => crate::sup::signal_context(m),
        _ => crate::sup::host_error(0, 0, proto::ctl::HE_RUNTIME_ASSERT),
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
    // A stop in a load-time plan's trampoline shows the program's own address
    // (`plans::shown`).
    let pc = crate::plans::shown(frame.pc);
    let mut sf = Sigframe {
        info: if flags & SA_SIGINFO != 0 { si } else { [0; 16] },
        uc: Frame { pc, ..*frame },
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
    uc.records = sigrec::program_records(&frame.records, syndrome).unwrap_or_else(|b| stop(b));
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
    charge_delivery(sig, handler, f, &si, pc, frame.sp);
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
    // The handler starts with TPIDR2 0 and POR_EL0 `POR_EL0_INIT` (streaming mode and ZA are
    // off already: `program_records` stops on them).
    if let Err(b) = sigrec::handler_entry(&mut frame.records) {
        stop(b)
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

/// The trap frame's new records from the program's frame `g` (`proto::sigrec::records_in`):
/// Err for a frame the kernel refuses.
fn records_in(g: &[u8; 4096], t: &[u8; 4096]) -> Result<[u8; 4096], ()> {
    match sigrec::records_in(g, t) {
        Ok(r) => Ok(r),
        Err(Bad::Refused) => Err(()),
        Err(b) => stop(b),
    }
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
