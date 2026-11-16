//! Guest signal frames: `deliver` builds the kernel's x86_64 `rt_sigframe` on the
//! stack the guest asked for and edits the trap frame so that returning from the trap
//! enters the guest handler; `sigreturn` is the emulation of the guest's `rt_sigreturn`.
//!
//! Layout (arch/x86/include/asm/sigframe.h, uapi sigcontext.h), offsets from the frame:
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 8 | `pretcode` (the guest's `sa_restorer`) |
//! | 8 | 304 | `ucontext`: `uc_flags` 8, `uc_link` 16, `uc_stack` 24 (sp, flags, size), `uc_mcontext` 48 (23 gregs, `fpstate` 232, reserved 240..304), `uc_sigmask` 304 |
//! | 312 | 128 | `siginfo` |
//!
//! The FP state lies above the frame, 64-byte aligned, `extended_size` bytes (from the
//! software-reserved bytes of the trap frame's FP state, not a constant). The frame's start
//! is `round_down(fp - 440, 16) - 8`, so that `(sp + 8) % 16 == 0` at the handler's entry,
//! below the 128-byte red zone of the interrupted code, or at the top of the guest's
//! alternate stack for `SA_ONSTACK`.

use crate::state::{ctl, proc, ThreadState};
use crate::sys::sig::*;
use crate::trap::{reg::*, TrapFrame};
use core::sync::atomic::Ordering::*;

pub const FRAME_SIZE: u64 = 440;
const UC_OFF: u64 = 8;
const INFO_OFF: u64 = 312;
const REDZONE: u64 = 128;

const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// Byte offsets inside an XSAVE image.
const SW_OFF: usize = 464;
const HDR_OFF: usize = 512;
const LEGACY_USED: usize = 416; // x87 + MXCSR + ST0-7 + XMM0-15
/// State components whose in-use bit is normalised (AVX .. PKRU). Later ones (AMX) are
/// copied as the kernel wrote them: setting their bits could fault on restore.
const NORMALISE: core::ops::RangeInclusive<u32> = 2..=9;

const X86_EFLAGS_CF: u64 = 0x1;
const X86_EFLAGS_PF: u64 = 0x4;
const X86_EFLAGS_AF: u64 = 0x10;
const X86_EFLAGS_ZF: u64 = 0x40;
const X86_EFLAGS_SF: u64 = 0x80;
const X86_EFLAGS_TF: u64 = 0x100;
const X86_EFLAGS_DF: u64 = 0x400;
const X86_EFLAGS_OF: u64 = 0x800;
const X86_EFLAGS_RF: u64 = 0x1_0000;
const X86_EFLAGS_AC: u64 = 0x4_0000;
/// Flags `rt_sigreturn` takes from the frame (the kernel's `FIX_EFLAGS`).
const FIX_EFLAGS: u64 = X86_EFLAGS_AC
    | X86_EFLAGS_OF
    | X86_EFLAGS_DF
    | X86_EFLAGS_TF
    | X86_EFLAGS_SF
    | X86_EFLAGS_ZF
    | X86_EFLAGS_AF
    | X86_EFLAGS_PF
    | X86_EFLAGS_CF
    | X86_EFLAGS_RF;

unsafe fn rd32(p: u64) -> u32 {
    core::ptr::read_unaligned(p as *const u32)
}
unsafe fn rd64(p: u64) -> u64 {
    core::ptr::read_unaligned(p as *const u64)
}
unsafe fn wr32(p: u64, v: u32) {
    core::ptr::write_unaligned(p as *mut u32, v)
}
unsafe fn wr64(p: u64, v: u64) {
    core::ptr::write_unaligned(p as *mut u64, v)
}
unsafe fn zero(p: u64, n: u64) {
    core::ptr::write_bytes(p as *mut u8, 0, n as usize)
}
unsafe fn copy(dst: u64, src: u64, n: u64) {
    core::ptr::copy(src as *const u8, dst as *mut u8, n as usize)
}

/// Sizes of an FP image: (xstate_size, extended_size, xfeatures); xstate_size 0 = legacy
/// FXSAVE image only (no magic).
unsafe fn fp_sizes(fp: u64) -> (u64, u64, u64) {
    let sw = fp + SW_OFF as u64;
    if rd32(sw) == FP_XSTATE_MAGIC1 {
        let ext = rd32(sw + 4) as u64;
        let xsize = rd32(sw + 16) as u64;
        if xsize >= 576 && ext == xsize + 4 && rd32(fp + xsize) == FP_XSTATE_MAGIC2 {
            return (xsize, ext, rd64(sw + 8));
        }
    }
    (0, 512, 3)
}

/// Standard-format offset and size of XSAVE component `i` (CPUID leaf 0xD).
fn component(i: u32) -> (u64, u64) {
    let p = proc();
    if p.xsave_off[i as usize] == 0 {
        let r = core::arch::x86_64::__cpuid_count(0xd, i);
        p.xsave_off[i as usize] = r.ebx;
        p.xsave_len[i as usize] = r.eax;
    }
    (
        p.xsave_off[i as usize] as u64,
        p.xsave_len[i as usize] as u64,
    )
}

/// Copy the trap frame's FP state to `dst` for the guest's frame: everything outside the
/// state components is zero, the software-reserved bytes are rewritten from the sizes, and
/// every component in AVX..PKRU is marked in use (its init value is all zeros), so the image
/// does not depend on which components the CPU happened to report as in initial state.
unsafe fn fp_copy_out(dst: u64, src: u64, xsize: u64, ext: u64, xfeatures: u64) {
    zero(dst, ext);
    copy(dst, src, LEGACY_USED as u64);
    if xsize == 0 {
        return;
    }
    let sw = dst + SW_OFF as u64;
    wr32(sw, FP_XSTATE_MAGIC1);
    wr32(sw + 4, ext as u32);
    wr64(sw + 8, xfeatures);
    wr32(sw + 16, xsize as u32);
    let mut bv = rd64(src + HDR_OFF as u64) & xfeatures;
    for i in 2..64u32 {
        if xfeatures & (1 << i) == 0 {
            continue;
        }
        let (off, len) = component(i);
        if off == 0 || off + len > xsize {
            continue;
        }
        if bv & (1 << i) != 0 {
            copy(dst + off, src + off, len);
        } else if NORMALISE.contains(&i) {
            bv |= 1 << i; // init value: the zeros already there
        }
    }
    wr64(dst + HDR_OFF as u64, bv | 3);
    wr32(dst + xsize, FP_XSTATE_MAGIC2);
}

/// The FP state a handler starts with (the kernel's `fpu__clear_user_states`): x87 and
/// SSE in their initial configuration, every other component initial, PKRU kept.
unsafe fn fp_init(fp: u64) {
    let (xsize, _, _) = fp_sizes(fp);
    let mxcsr_mask = rd32(fp + 28);
    zero(fp, SW_OFF as u64);
    core::ptr::write_unaligned(fp as *mut u16, 0x37f);
    wr32(fp + 24, 0x1f80);
    wr32(fp + 28, mxcsr_mask);
    if xsize != 0 {
        let pkru = rd64(fp + HDR_OFF as u64) & (1 << 9);
        zero(fp + HDR_OFF as u64, 64);
        wr64(fp + HDR_OFF as u64, 3 | pkru);
    }
}

/// Load the guest's FP image `src` into the trap frame's `dst` (`rt_sigreturn`).
unsafe fn fp_copy_in(dst: u64, src: u64) {
    if src == 0 {
        fp_init(dst);
        return;
    }
    let (dsize, _, dfeat) = fp_sizes(dst);
    let (ssize, _, _) = fp_sizes(src);
    copy(dst, src, SW_OFF as u64);
    if dsize == 0 {
        return;
    }
    if ssize == 0 {
        // A legacy (FXSAVE-only) image: x87 and SSE from it, everything else initial.
        zero(dst + HDR_OFF as u64, 64);
        wr64(dst + HDR_OFF as u64, 3);
        return;
    }
    let n = ssize.min(dsize);
    copy(
        dst + HDR_OFF as u64,
        src + HDR_OFF as u64,
        n - HDR_OFF as u64,
    );
    // A header XRSTOR would refuse (compacted, reserved bits) is made valid.
    let bv = rd64(dst + HDR_OFF as u64) & dfeat;
    zero(dst + HDR_OFF as u64, 64);
    wr64(dst + HDR_OFF as u64, bv);
}

/// Build a frame for `sig` with handler `act` and edit the trap frame to enter it.
/// `fault`: a synchronous fault, whose trap number, error code and `cr2` the frame keeps;
/// for any other signal they are 0 (the kernel leaves whatever the thread's last exception
/// set, which here would include the runtime's own `rdtsc` emulation).
pub fn deliver(
    frame: &mut TrapFrame,
    ts: &mut ThreadState,
    sig: u64,
    info: &SigInfo,
    act: [u64; 4],
    fault: bool,
) {
    let [handler, flags, restorer, sa_mask] = act;
    let orig_sp = frame.gregs[RSP];
    let mask = if ts.has_saved != 0 {
        ts.saved_mask
    } else {
        ts.vmask
    };
    let valt = ts.valt;
    let nested = on_sig_stack(&valt, orig_sp);
    let mut sp = orig_sp.wrapping_sub(REDZONE);
    let mut entering = false;
    if flags & SA_ONSTACK != 0 && sas_ss_flags(&valt, sp) == 0 {
        sp = valt[0] + valt[2];
        entering = true;
    }
    let src = frame.fpstate;
    let (xsize, ext, xfeatures) = if src != 0 {
        unsafe { fp_sizes(src) }
    } else {
        (0, 0, 0)
    };
    let fp = if src != 0 { (sp - ext) & !63 } else { sp };
    let f = ((fp - FRAME_SIZE) & !15) - 8;
    if (nested || entering) && !(f > valt[0] && f - valt[0] <= valt[2]) {
        // The kernel's "overflowed sigaltstack": the process gets SIGSEGV.
        die(SIGSEGV);
    }
    charge_delivery(sig, handler, f, info, frame);
    unsafe {
        if src != 0 {
            fp_copy_out(fp, src, xsize, ext, xfeatures);
        }
        zero(f, FRAME_SIZE);
        wr64(f, restorer);
        let uc = f + UC_OFF;
        let g = &mut *(uc as *mut TrapFrame);
        g.uc_flags = frame.uc_flags;
        g.uc_link = 0;
        g.ss_sp = valt[0];
        g.ss_flags = valt[1] as u32;
        g.ss_size = valt[2];
        g.gregs = frame.gregs;
        g.gregs[OLDMASK] = mask;
        if !fault {
            g.gregs[ERR] = 0;
            g.gregs[TRAPNO] = 0;
            g.gregs[CR2] = 0;
        }
        g.fpstate = if src != 0 { fp } else { 0 };
        g.reserved = [0; 8];
        g.sigmask = mask;
        // The kernel writes siginfo only for SA_SIGINFO handlers (the bytes are otherwise
        // whatever the stack held; here they stay zero).
        if flags & SA_SIGINFO != 0 {
            core::ptr::copy_nonoverlapping(
                info.as_ptr() as *const u8,
                (f + INFO_OFF) as *mut u8,
                128,
            );
        }
        if src != 0 {
            fp_init(src);
        }
    }
    let r = &mut frame.gregs;
    r[RDI] = sig;
    r[RAX] = 0;
    r[RSI] = f + INFO_OFF;
    r[RDX] = f + UC_OFF;
    r[RIP] = handler;
    r[RSP] = f;
    r[EFL] &= !(X86_EFLAGS_DF | X86_EFLAGS_RF | X86_EFLAGS_TF);
    // The mask while the handler runs.
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

/// A delivery is a boundary event of its own.
fn charge_delivery(sig: u64, handler: u64, f: u64, info: &SigInfo, frame: &TrapFrame) {
    let ts = crate::state::thread();
    crate::entry::charge(ts);
    let c = ctl();
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        slot: ts.slot as u16,
        kind: proto::RecKind::SignalDelivery as u8,
        class: 0,
        nr: sig as u32,
        args: [
            handler,
            f,
            info[1] & 0xffff_ffff,
            frame.gregs[RIP],
            frame.gregs[RSP],
            ts.vmask,
        ],
        ret: 0,
        out_hash: proto::rec::hash_bytes(0, unsafe {
            core::slice::from_raw_parts(info.as_ptr() as *const u8, 128)
        }),
        in_hash: 0,
    };
    crate::log::append(&rec);
}

/// Emulated `rt_sigreturn`: the guest's handler returned through its restorer, so the
/// guest stack pointer is just above `pretcode`, at the frame's `ucontext`. Registers, FP
/// state, mask and alternate stack come from that `ucontext`, including any change the
/// handler made to it. Returns the restored `rax`.
pub fn sigreturn(frame: &mut TrapFrame, ts: &mut ThreadState) -> i64 {
    let uc = frame.gregs[RSP];
    let g = unsafe { &*(uc as *const TrapFrame) };
    let efl = frame.gregs[EFL];
    for i in 0..=RIP {
        frame.gregs[i] = g.gregs[i];
    }
    frame.gregs[EFL] = (efl & !FIX_EFLAGS) | (g.gregs[EFL] & FIX_EFLAGS);
    if frame.fpstate != 0 {
        unsafe { fp_copy_in(frame.fpstate, g.fpstate) };
    }
    set_vmask(ts, g.sigmask);
    // `restore_altstack`: errors (for example "on the stack now") are ignored.
    let _ = set_altstack(ts, [g.ss_sp, g.ss_flags as u64, g.ss_size], uc);
    frame.gregs[RAX] as i64
}
