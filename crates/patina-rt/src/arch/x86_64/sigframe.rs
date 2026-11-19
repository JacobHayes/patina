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

use crate::arch::{reg::*, Frame};
use crate::state::{proc, ThreadState};
use crate::sys::sig::*;

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

// Accessors of the runtime's own memory (the trap frame's FP state). The program's memory is
// reached only through the guest copy (`crate::guest`), which answers `Err` where the kernel's
// user copy would fault.
unsafe fn rd32(p: u64) -> u32 {
    core::ptr::read_unaligned(p as *const u32)
}
unsafe fn rd64(p: u64) -> u64 {
    core::ptr::read_unaligned(p as *const u64)
}
unsafe fn wr64(p: u64, v: u64) {
    core::ptr::write_unaligned(p as *mut u64, v)
}
unsafe fn zero(p: u64, n: u64) {
    core::ptr::write_bytes(p as *mut u8, 0, n as usize)
}
unsafe fn bytes<'a>(p: u64, n: u64) -> &'a [u8] {
    core::slice::from_raw_parts(p as *const u8, n as usize)
}
unsafe fn bytes_mut<'a>(p: u64, n: u64) -> &'a mut [u8] {
    core::slice::from_raw_parts_mut(p as *mut u8, n as usize)
}

/// A program frame the kernel could not read or write (its user copy faulted).
struct Fault;
impl From<i64> for Fault {
    fn from(_: i64) -> Fault {
        Fault
    }
}

/// Sizes of an FP image: (xstate_size, extended_size, xfeatures); xstate_size 0 = legacy
/// FXSAVE image only (no magic). `rd32` reads the image (`Err`: unreadable, as the kernel's
/// `check_xstate_in_sigframe` fails on a fault).
fn fp_sizes_by(
    fp: u64,
    rd32: impl Fn(u64) -> Result<u32, Fault>,
) -> Result<(u64, u64, u64), Fault> {
    let sw = fp + SW_OFF as u64;
    if rd32(sw)? == FP_XSTATE_MAGIC1 {
        let ext = rd32(sw + 4)? as u64;
        let xsize = rd32(sw + 16)? as u64;
        if xsize >= 576 && ext == xsize + 4 && rd32(fp + xsize)? == FP_XSTATE_MAGIC2 {
            let xfeatures = rd32(sw + 8)? as u64 | (rd32(sw + 12)? as u64) << 32;
            return Ok((xsize, ext, xfeatures));
        }
    }
    Ok((0, 512, 3))
}

/// `fp_sizes_by` of the runtime's own memory (the trap frame's FP state, written by the kernel).
fn fp_sizes(fp: u64) -> (u64, u64, u64) {
    match fp_sizes_by(fp, |p| Ok(unsafe { rd32(p) })) {
        Ok(s) => s,
        Err(Fault) => unreachable!(),
    }
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

/// Copy the trap frame's FP state `src` to the program's memory at `dst` for its frame:
/// everything outside the state components is zero, the software-reserved bytes are rewritten
/// from the sizes, and every component in AVX..PKRU is marked in use (its init value is all
/// zeros), so the image does not depend on which components the CPU happened to report as in
/// initial state.
fn fp_copy_out(dst: u64, src: u64, xsize: u64, ext: u64, xfeatures: u64) -> Result<(), Fault> {
    crate::guest::zero(dst, ext as usize)?;
    crate::guest::write(dst, unsafe { bytes(src, LEGACY_USED as u64) })?;
    if xsize == 0 {
        return Ok(());
    }
    let sw = dst + SW_OFF as u64;
    crate::guest::put(sw, FP_XSTATE_MAGIC1)?;
    crate::guest::put(sw + 4, ext as u32)?;
    crate::guest::put(sw + 8, xfeatures)?;
    crate::guest::put(sw + 16, xsize as u32)?;
    let mut bv = unsafe { rd64(src + HDR_OFF as u64) } & xfeatures;
    for i in 2..64u32 {
        if xfeatures & (1 << i) == 0 {
            continue;
        }
        let (off, len) = component(i);
        if off == 0 || off + len > xsize {
            continue;
        }
        if bv & (1 << i) != 0 {
            crate::guest::write(dst + off, unsafe { bytes(src + off, len) })?;
        } else if NORMALISE.contains(&i) {
            bv |= 1 << i; // init value: the zeros already there
        }
    }
    crate::guest::put(dst + HDR_OFF as u64, bv | 3)?;
    crate::guest::put(dst + xsize, FP_XSTATE_MAGIC2)?;
    Ok(())
}

/// The FP state a handler starts with (the kernel's `fpu__clear_user_states`): x87 and
/// SSE in their initial configuration, every other component initial, PKRU kept.
unsafe fn fp_init(fp: u64) {
    let (xsize, _, _) = fp_sizes(fp);
    let mxcsr_mask = rd32(fp + 28);
    zero(fp, SW_OFF as u64);
    core::ptr::write_unaligned(fp as *mut u16, 0x37f);
    core::ptr::write_unaligned((fp + 24) as *mut u32, 0x1f80);
    core::ptr::write_unaligned((fp + 28) as *mut u32, mxcsr_mask);
    if xsize != 0 {
        let pkru = rd64(fp + HDR_OFF as u64) & (1 << 9);
        zero(fp + HDR_OFF as u64, 64);
        wr64(fp + HDR_OFF as u64, 3 | pkru);
    }
}

/// Load the program's FP image at `src` into the trap frame's `dst` (`rt_sigreturn`). `Err`
/// where the kernel's restore fails: the image cannot be read, or `FXRSTOR`/`XRSTOR` would
/// fault on it (a reserved `MXCSR` bit; a header in compacted form, with reserved bytes set
/// or naming a component the host does not enable). `dst` is then partly written, and the
/// caller resets it.
fn fp_copy_in(dst: u64, src: u64) -> Result<(), Fault> {
    if src == 0 {
        unsafe { fp_init(dst) };
        return Ok(());
    }
    let (dsize, _, dfeat) = fp_sizes(dst);
    let mxcsr_mask = match unsafe { rd32(dst + 28) } {
        0 => 0xffbf,
        m => m,
    };
    let (ssize, _, _) = fp_sizes_by(src, |p| Ok(crate::guest::get::<u32>(p)?))?;
    crate::guest::read(src, unsafe { bytes_mut(dst, SW_OFF as u64) })?;
    if unsafe { rd32(dst + 24) } & !mxcsr_mask != 0 {
        return Err(Fault);
    }
    if dsize == 0 {
        return Ok(());
    }
    unsafe {
        if ssize == 0 {
            // A legacy (FXSAVE-only) image: x87 and SSE from it, everything else initial.
            zero(dst + HDR_OFF as u64, 64);
            wr64(dst + HDR_OFF as u64, 3);
            return Ok(());
        }
        let n = ssize.min(dsize);
        crate::guest::read(
            src + HDR_OFF as u64,
            bytes_mut(dst + HDR_OFF as u64, n - HDR_OFF as u64),
        )?;
        let hdr = core::ptr::read_unaligned((dst + HDR_OFF as u64) as *const [u64; 8]);
        if hdr[0] & !dfeat != 0 || hdr[1..].iter().any(|&w| w != 0) {
            return Err(Fault);
        }
    }
    Ok(())
}

const SI_KERNEL: i32 = 0x80;

/// The frame as written to the program's stack.
#[repr(C)]
struct Sigframe {
    pretcode: u64,
    uc: Frame,
    info: SigInfo,
}
const _: () = assert!(core::mem::size_of::<Sigframe>() as u64 == FRAME_SIZE);
const _: () = assert!(core::mem::offset_of!(Sigframe, uc) as u64 == UC_OFF);
const _: () = assert!(core::mem::offset_of!(Sigframe, info) as u64 == INFO_OFF);

/// Build a frame for `sig` with handler `act` and edit the trap frame to enter it.
/// `fault`: a synchronous fault, whose trap number, error code and `cr2` the frame keeps;
/// for any other signal they are 0 (the kernel leaves whatever the thread's last exception
/// set, which here would include the runtime's own `rdtsc` emulation). A handler installed
/// without `SA_RESTORER`, a frame that overflows the alternate stack, and one the kernel could
/// not write are its failed delivery: SIGSEGV (`force_sigsegv`).
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
    // `x64_setup_rt_frame`: x86_64 delivers only to a handler with its own restorer.
    let f = if flags & SA_RESTORER != 0 {
        write_frame(frame, ts, info, flags, restorer, mask, fault)
    } else {
        Err(Fault)
    };
    let Ok(f) = f else {
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
    };
    charge_delivery(
        sig,
        handler,
        f,
        info,
        crate::plans::shown(frame.gregs[RIP]),
        frame.gregs[RSP],
    );
    if frame.fpstate != 0 {
        unsafe { fp_init(frame.fpstate) };
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

/// `get_sigframe` and the frame's writes: the frame's address, or `Err` where the kernel's
/// delivery fails (an overflowed alternate stack, a write that faults).
fn write_frame(
    frame: &Frame,
    ts: &ThreadState,
    info: &SigInfo,
    flags: u64,
    restorer: u64,
    mask: u64,
    fault: bool,
) -> Result<u64, Fault> {
    let orig_sp = frame.gregs[RSP];
    let valt = ts.valt;
    let nested = on_sig_stack(&valt, orig_sp);
    let mut sp = orig_sp.wrapping_sub(REDZONE);
    let mut entering = false;
    if flags & SA_ONSTACK != 0 && sas_ss_flags(&valt, sp) == 0 {
        sp = valt[0].wrapping_add(valt[2]);
        entering = true;
    }
    let src = frame.fpstate;
    let (xsize, ext, xfeatures) = if src != 0 { fp_sizes(src) } else { (0, 0, 0) };
    let fp = if src != 0 {
        sp.wrapping_sub(ext) & !63
    } else {
        sp
    };
    let f = (fp.wrapping_sub(FRAME_SIZE) & !15).wrapping_sub(8);
    if (nested || entering) && !(f > valt[0] && f - valt[0] <= valt[2]) {
        // The kernel's "overflowed sigaltstack".
        return Err(Fault);
    }
    if src != 0 {
        fp_copy_out(fp, src, xsize, ext, xfeatures)?;
    }
    let mut uc = Frame {
        uc_flags: frame.uc_flags,
        uc_link: 0,
        ss_sp: valt[0],
        ss_flags: valt[1] as u32,
        _pad: 0,
        ss_size: valt[2],
        gregs: frame.gregs,
        fpstate: if src != 0 { fp } else { 0 },
        reserved: [0; 8],
        sigmask: mask,
    };
    uc.gregs[OLDMASK] = mask;
    let pc = uc.gregs[RIP];
    uc.gregs[RIP] = crate::plans::shown(pc);
    if !fault {
        uc.gregs[ERR] = 0;
        uc.gregs[TRAPNO] = 0;
        uc.gregs[CR2] = 0;
    }
    let sf = Sigframe {
        pretcode: restorer,
        uc,
        // The kernel writes siginfo only for SA_SIGINFO handlers (the bytes are otherwise
        // whatever the stack held; here they are zero).
        info: if flags & SA_SIGINFO != 0 {
            // A fault's address that is the instruction's (SIGILL, SIGFPE, a fetch) is shown
            // as the instruction is.
            let mut i = *info;
            let (signo, code) = (i[0] as u32, i[1] as u32 as i32);
            if matches!(signo, 4 | 5 | 7 | 8 | 11) && code > 0 && i[2] == pc {
                i[2] = uc.gregs[RIP];
            }
            i
        } else {
            [0; 16]
        },
    };
    let b = unsafe {
        core::slice::from_raw_parts(
            &sf as *const Sigframe as *const u8,
            core::mem::size_of::<Sigframe>(),
        )
    };
    crate::guest::write(f, b)?;
    Ok(f)
}

/// Emulated `rt_sigreturn`: the guest's handler returned through its restorer, so the
/// guest stack pointer is just above `pretcode`, at the frame's `ucontext`. Registers, FP
/// state, mask and alternate stack come from that `ucontext`, including any change the
/// handler made to it. A frame the kernel cannot read gives the program SIGSEGV, as natively;
/// the runtime reads it only through the guest copy. Returns the restored `rax`.
pub fn sigreturn(frame: &mut Frame, ts: &mut ThreadState) -> i64 {
    // `restore_sigcontext`: a restart block a handler left is never continued after it.
    ts.restart = [RB_NONE; 5];
    if restore(frame, ts).is_err() {
        // `badframe`: the call returns 0, then `signal_fault` forces SIGSEGV.
        frame.gregs[RAX] = 0;
        force(
            frame,
            ts,
            SIGSEGV,
            &siginfo(SIGSEGV, SI_KERNEL, 0, 0),
            false,
        );
    }
    frame.gregs[RAX] as i64
}

/// The kernel's `rt_sigreturn` up to its `badframe`: registers and mask may be changed before
/// a refusal, as the kernel changes them; an FP image that cannot be read leaves the FP state
/// initial (`fpu__clear_user_states`).
fn restore(frame: &mut Frame, ts: &mut ThreadState) -> Result<(), Fault> {
    let uc = frame.gregs[RSP];
    // The guest copy may read the thread's own runtime stack (for the runtime's own buffers);
    // a frame there is not the program's: it reads as unmapped.
    let end = uc.wrapping_add(core::mem::size_of::<Frame>() as u64);
    if uc < proto::layout::RT_REGION_END && end > proto::layout::RT_BASE {
        return Err(Fault);
    }
    let g = crate::guest::get::<Frame>(uc)?;
    set_vmask(ts, g.sigmask);
    let efl = frame.gregs[EFL];
    for i in 0..=RIP {
        frame.gregs[i] = g.gregs[i];
    }
    frame.gregs[EFL] = (efl & !FIX_EFLAGS) | (g.gregs[EFL] & FIX_EFLAGS);
    if frame.fpstate != 0 {
        let fp = frame.fpstate;
        // What `fpu__clear_user_states` keeps of the thread's own state: the MXCSR mask (a
        // fact of the CPU) and PKRU, whatever a refused image held.
        let mask = unsafe { rd32(fp + 28) };
        let (xsize, _, xfeatures) = fp_sizes(fp);
        let (pkru_off, _) = component(9);
        let pkru =
            (xsize != 0 && xfeatures & 1 << 9 != 0 && pkru_off != 0 && pkru_off + 4 <= xsize)
                .then(|| unsafe { (rd64(fp + HDR_OFF as u64) & 1 << 9, rd32(fp + pkru_off)) });
        if fp_copy_in(fp, g.fpstate).is_err() {
            unsafe {
                core::ptr::write_unaligned((fp + 28) as *mut u32, mask);
                if let Some((bv, v)) = pkru {
                    let h = fp + HDR_OFF as u64;
                    wr64(h, rd64(h) & !(1 << 9) | bv);
                    core::ptr::write_unaligned((fp + pkru_off) as *mut u32, v);
                }
                fp_init(fp);
            }
            return Err(Fault);
        }
    }
    // `restore_altstack`: errors (for example "on the stack now") are ignored.
    let _ = set_altstack(ts, [g.ss_sp, g.ss_flags as u64, g.ss_size], uc);
    Ok(())
}
