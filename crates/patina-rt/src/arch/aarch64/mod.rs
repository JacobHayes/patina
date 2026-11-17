//! aarch64: `svc #0`, the number in `x8`, arguments in `x0`-`x5`, the result in `x0` (the
//! first argument's register: the kernel restores the argument before SIGSYS, and the trap
//! entry copies the arguments out before any handler runs).

mod entry;
mod guest;
pub mod insn;
mod sigframe;
pub mod step;
mod stub;
mod thread;

pub use entry::{enter_guest, restorer, switch_stack};
pub use guest::{current_sp, fixup, guest_copy};
pub use sigframe::{deliver, sigreturn};
pub use stub::{sc6, stub_escape, stub_ip};
pub use thread::{clone_vm, frame_extent, rebase_frame, sigreturn_to};

/// The seccomp program's architecture (`seccomp_data.arch`).
pub const AUDIT_ARCH: u32 = 0xC000_00B7;

/// Bytes of the system-call instruction: the kernel's reported address is this far past it.
pub const SYSCALL_LEN: u64 = 4;

/// `clone`'s arguments by role, from the raw ones: (flags, stack, ptid, ctid, tls). The
/// generic order (`CONFIG_CLONE_BACKWARDS`) has the TLS before the child's tid pointer.
#[inline(always)]
pub fn clone_args(a: [u64; 6]) -> [u64; 5] {
    [a[0], a[1], a[2], a[4], a[3]]
}

/// The value the program sees for an auxiliary vector entry copied from the kernel's: the
/// host's (host-stable facts), less three features, plus `HWCAP2_RNG` when `RNDR` is answered
/// from the seed on a host without it (`insn::rndr_on`, a test of that path).
/// - `HWCAP_PACG`: the generic key cannot be disabled, so `PACGA` would give a different value
///   in every run (the scan counts the program's sites, `insn`).
/// - SME (`HWCAP2_SME` and every SME sub-feature, some in `AT_HWCAP`): with it hidden,
///   libraries that choose code by the auxiliary vector (glibc, language runtimes) never turn
///   on streaming mode or the ZA array, whose contents and vector length are the host's.
///   Instructions are not checked: a program that executes SME anyway computes
///   deterministically on that host. (The kernel's signal frames and `AT_MINSIGSTKSZ` still
///   carry the SME records on an SME host: seeds and digests are per kind of host.)
/// - `HWCAP_CPUID`: the kernel emulates `mrs` of the ID registers, and `MIDR_EL1` answers
///   for the core the thread runs on, which on a host with two kinds of core changes between
///   runs. glibc reads it only when the bit is set (to choose `memcpy`).
pub fn aux_value(t: u64, v: u64) -> u64 {
    const AT_HWCAP: u64 = 16;
    const AT_HWCAP2: u64 = 26;
    const HWCAP_CPUID: u64 = 1 << 11;
    const HWCAP_PACG: u64 = 1 << 31;
    // HWCAP_SME2P2, SME_SBITPERM, SME_AES, SME_SFEXPA, SME_STMOP, SME_SMOP4.
    const HWCAP_SME: u64 = 0x3f << 42;
    match t {
        AT_HWCAP => v & !(HWCAP_PACG | HWCAP_CPUID | HWCAP_SME),
        AT_HWCAP2 if insn::rndr_on() => v & !HWCAP2_SME_ALL | insn::HWCAP2_RNG,
        AT_HWCAP2 => v & !HWCAP2_SME_ALL,
        _ => v,
    }
}

/// `HWCAP2_SME` and its sub-features: bits 23-30 (SME .. SME_FA64), 37-42 (SME2 ..
/// SME_F16F16) and 57-62 (SME_LUTV2 .. SME_SF8DP2).
const HWCAP2_SME_ALL: u64 = 0xff << 23 | 0x3f << 37 | 0x3f << 57;

/// Whether `/proc/cpuinfo`'s `Features` line leaves out the word `w`: the features
/// `aux_value` hides.
pub fn feature_hidden(w: &[u8]) -> bool {
    w == b"pacg" || w == b"cpuid" || w.starts_with(b"sme")
}

/// `sigaction` flags Patina keeps beyond the generic ones (`sys::sig`'s `SA_KNOWN`):
/// `SA_EXPOSE_TAGBITS` (a fault's `si_addr` keeps the top byte).
pub const SA_ARCH_KNOWN: u64 = crate::sys::sig::SA_EXPOSE_TAGBITS;
/// Flags of the runtime's own fault and trap handlers beyond the generic ones:
/// `SA_EXPOSE_TAGBITS`, so a fault's address reaches the runtime whole, and a program handler
/// that asked for the tag gets it (`sigframe::deliver` clears it for the others).
pub const SA_ARCH_RUNTIME: u64 = crate::sys::sig::SA_EXPOSE_TAGBITS;

/// A fault address as an access resolves it: the top byte is ignored (the kernel's
/// `untagged_addr`: bit 55 extended over it).
#[inline(always)]
pub fn untagged(a: u64) -> u64 {
    ((a << 8) as i64 >> 8) as u64
}

/// Whether the host has branch target identification (`HWCAP2_BTI`): a handler is then
/// entered as an indirect call is (`sigframe::deliver`). Set by `image_init`.
static HOST_BTI: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn host_bti() -> bool {
    HOST_BTI.load(core::sync::atomic::Ordering::Relaxed)
}

/// Per-image setup of the program's address space, at the loader's start: note the host's
/// BTI from the kernel's `AT_HWCAP2` and map the signal restorer page (`sigframe`).
pub fn image_init(hwcap2: u64) {
    const HWCAP2_BTI: u64 = 1 << 17;
    HOST_BTI.store(
        hwcap2 & HWCAP2_BTI != 0,
        core::sync::atomic::Ordering::Relaxed,
    );
    sigframe::map_restorer();
}

/// Per-image setup that must come before anything else: the pointer-authentication keys off.
/// Every image starts with all four enabled and freshly drawn (exec), so a pointer the program
/// signs would differ from run to run. With the keys disabled the sign and authenticate
/// instructions do nothing. Fork inherits the setting; the runtime runs this at every image
/// start. A CPU or kernel without pointer authentication refuses both calls: nothing to do.
pub fn process_init() {
    const PR_PAC_SET_ENABLED_KEYS: u64 = 60;
    const PR_PAC_GET_ENABLED_KEYS: u64 = 61;
    const ALL_KEYS: u64 = 0xf; // APIA | APIB | APDA | APDB
    let r = unsafe {
        sc6(
            crate::raw::nr::PRCTL,
            PR_PAC_SET_ENABLED_KEYS,
            ALL_KEYS,
            0,
            0,
            0,
            0,
        )
    };
    if r == 0 {
        return;
    }
    let keys = unsafe {
        sc6(
            crate::raw::nr::PRCTL,
            PR_PAC_GET_ENABLED_KEYS,
            0,
            0,
            0,
            0,
            0,
        )
    };
    if keys != -22 {
        crate::fatal(proto::ctl::Setup::PacKeys, r);
    }
}

/// The number of words `Frame::regs_for_record` gives.
pub const RECORD_WORDS: usize = 34;

/// The kernel's `ucontext` as delivered on the alternate stack (`uapi/asm/ucontext.h`,
/// `sigcontext.h`): `uc_sigmask` at 40, `uc_mcontext` at 176, the records at 464.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Frame {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub ss_sp: u64,
    pub ss_flags: u32,
    pub _pad: u32,
    pub ss_size: u64,
    pub sigmask: u64,
    _unused: [u64; 15],
    _align: u64,
    pub fault_address: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    _pad2: u64,
    /// The context records (`_aarch64_ctx` headers: magic, size), ending in a zero header.
    pub records: [u8; 4096],
}

const _: () = {
    assert!(core::mem::offset_of!(Frame, sigmask) == 40);
    assert!(core::mem::offset_of!(Frame, fault_address) == 176);
    assert!(core::mem::offset_of!(Frame, regs) == 184);
    assert!(core::mem::offset_of!(Frame, sp) == 432);
    assert!(core::mem::offset_of!(Frame, pc) == 440);
    assert!(core::mem::offset_of!(Frame, pstate) == 448);
    assert!(core::mem::offset_of!(Frame, records) == 464);
    assert!(core::mem::size_of::<Frame>() == 4560);
};

/// The ESR record: the fault's exception syndrome, present when the thread has one.
pub(crate) const ESR_MAGIC: u32 = 0x4553_5201;
/// ESR_EL1 exception class of a data abort from a lower exception level.
const EC_DABT_LOW: u64 = 0x24;
/// ISS bit of a data abort: write, not read.
const ESR_WNR: u64 = 1 << 6;

impl Frame {
    /// The interrupted instruction pointer (after the call for SIGSYS, at the instruction for
    /// a fault).
    #[inline(always)]
    pub fn pc(&self) -> u64 {
        self.pc
    }
    #[inline(always)]
    pub fn set_pc(&mut self, v: u64) {
        self.pc = v;
    }
    #[inline(always)]
    pub fn sp(&self) -> u64 {
        self.sp
    }
    #[inline(always)]
    pub fn set_sp(&mut self, v: u64) {
        self.sp = v;
    }
    /// The system-call number of a SIGSYS frame.
    #[inline(always)]
    pub fn nr(&self) -> u64 {
        self.regs[8]
    }
    /// The six arguments of a SIGSYS frame (`x0` already restored by the kernel).
    #[inline(always)]
    pub fn args(&self) -> [u64; 6] {
        let r = &self.regs;
        [r[0], r[1], r[2], r[3], r[4], r[5]]
    }
    /// The result register.
    #[inline(always)]
    pub fn ret(&self) -> i64 {
        self.regs[0] as i64
    }
    #[inline(always)]
    pub fn set_ret(&mut self, r: i64) {
        self.regs[0] = r as u64;
    }
    /// Re-execute the system call `nr` when the frame is returned to. Valid before a result
    /// is written: `x0` still holds the first argument.
    #[inline(always)]
    pub fn rewind(&mut self, nr: u64) {
        self.regs[8] = nr;
        self.pc -= SYSCALL_LEN;
    }
    /// Re-execute the call `nr` after a result was written (`sys::sig`'s restarts): the
    /// result overwrote the first argument's register, so `x0` gets `arg0` back (the kernel's
    /// `orig_x0`).
    #[inline(always)]
    pub fn restart_after_result(&mut self, nr: u64, arg0: u64) {
        self.regs[0] = arg0;
        self.rewind(nr);
    }
    /// The words a preempt record hashes: `x0`-`x30`, `sp`, `pc` and the condition flags of
    /// `pstate` (its other bits are set by the kernel and the CPU: speculation controls, PAN,
    /// `BTYPE`).
    pub fn regs_for_record(&self) -> [u64; RECORD_WORDS] {
        const NZCV: u64 = 0xf000_0000;
        let mut words = [0u64; RECORD_WORDS];
        words[..31].copy_from_slice(&self.regs);
        words[31] = self.sp;
        words[32] = self.pc;
        words[33] = self.pstate & NZCV;
        words
    }
    /// The value of general register `n` as an instruction names it (31 = the zero register).
    #[inline(always)]
    pub fn set_xreg(&mut self, n: usize, v: u64) {
        if n < 31 {
            self.regs[n] = v;
        }
    }
    /// Whether the fault of this frame was a store: the ESR record's data-abort write bit.
    /// No record (a fault without a syndrome) is a load.
    pub fn fault_is_store(&self) -> bool {
        let mut off = 0usize;
        while off + 16 <= self.records.len() {
            let h = &self.records[off..];
            let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
            if magic == 0 || size < 8 {
                return false;
            }
            if magic == ESR_MAGIC {
                let mut e = [0u8; 8];
                e.copy_from_slice(&h[8..16]);
                let esr = u64::from_le_bytes(e);
                return esr >> 26 == EC_DABT_LOW && esr & ESR_WNR != 0;
            }
            off += size;
        }
        false
    }
}
