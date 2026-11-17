//! aarch64: `svc #0`, the number in `x8`, arguments in `x0`-`x5`, the result in `x0` (the
//! first argument's register: the kernel restores the argument before SIGSYS, and the trap
//! entry copies the arguments out before any handler runs).

mod entry;
mod guest;
mod stub;

pub use entry::{enter_guest, restorer, switch_stack};
pub use guest::{current_sp, fixup, guest_copy};
pub use stub::{sc6, stub_escape, stub_ip};

/// The seccomp program's architecture (`seccomp_data.arch`).
pub const AUDIT_ARCH: u32 = 0xC000_00B7;

/// Bytes of the system-call instruction: the kernel's reported address is this far past it.
pub const SYSCALL_LEN: u64 = 4;

/// The value the program sees for an auxiliary vector entry copied from the kernel's.
/// `HWCAP_PACG` is cleared: the generic key cannot be disabled, so `PACGA` would give a
/// different value in every run (the scan stops a program that has one, `insn`).
pub fn aux_value(t: u64, v: u64) -> u64 {
    const AT_HWCAP: u64 = 16;
    const HWCAP_PACG: u64 = 1 << 31;
    if t == AT_HWCAP {
        v & !HWCAP_PACG
    } else {
        v
    }
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

/// The kernel's `ucontext` as delivered on the alternate stack (`uapi/asm/ucontext.h`,
/// `sigcontext.h`): `uc_sigmask` at 40, `uc_mcontext` at 176, the records at 464.
#[repr(C, align(16))]
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
const ESR_MAGIC: u32 = 0x4553_5201;
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
    /// Re-execute the call `nr` after a result was written (`sys::sig`'s restarts): needs the
    /// first argument back in `x0`, which signal delivery (not ported yet) must keep.
    pub fn restart_after_result(&mut self, _nr: u64) {
        crate::sup::unported(proto::ctl::UNPORTED_SIGNALS)
    }
    /// The words a preempt record hashes (compute points: not ported yet).
    pub fn regs_for_record(&self) -> [u64; 18] {
        crate::sup::unported(proto::ctl::UNPORTED_COMPUTE)
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
