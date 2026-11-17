//! x86_64: `syscall`, the number in `rax`, arguments in `rdi rsi rdx r10 r8 r9`, the result
//! in `rax`.

mod cmem;
mod entry;
mod guest;
pub mod insn;
mod sigframe;
mod stub;
mod thread;

pub use entry::{enter_guest, restorer, switch_stack};
pub use guest::{current_sp, fixup, guest_copy};
pub use sigframe::{deliver, sigreturn};
pub use stub::{sc6, stub_escape, stub_ip};
pub use thread::{clone_vm, frame_extent, rebase_frame, sigreturn_to};

/// The seccomp program's architecture (`seccomp_data.arch`).
pub const AUDIT_ARCH: u32 = 0xC000_003E;

/// Bytes of the system-call instruction: the kernel's reported address is this far past it.
pub const SYSCALL_LEN: u64 = 2;

/// `clone`'s arguments by role, from the raw ones: (flags, stack, ptid, ctid, tls).
#[inline(always)]
pub fn clone_args(a: [u64; 6]) -> [u64; 5] {
    [a[0], a[1], a[2], a[3], a[4]]
}

/// `sigaction` flags Patina keeps beyond the generic ones (`sys::sig`'s `SA_KNOWN`): none here
/// (the kernel also keeps `SA_EXPOSE_TAGBITS`, which has no effect on x86_64).
pub const SA_ARCH_KNOWN: u64 = 0;
/// Flags of the runtime's own fault and trap handlers beyond the generic ones: none here.
pub const SA_ARCH_RUNTIME: u64 = 0;

/// A fault address as an access resolves it: no tag bits on x86_64.
#[inline(always)]
pub fn untagged(a: u64) -> u64 {
    a
}

/// Per-image setup of the program's address space, at the loader's start: nothing on x86_64
/// (handlers name their restorer, `SA_RESTORER`).
#[inline(always)]
pub fn image_init(_hwcap2: u64) {}

/// Per-image setup that must come before anything else: none on x86_64 (the counter trap is
/// set in `rt_main`, `insn::tsc::ensure_faulting`).
#[inline(always)]
pub fn process_init() {}

/// The value the program sees for an auxiliary vector entry copied from the kernel's: the
/// kernel's, on x86_64.
#[inline(always)]
pub fn aux_value(_t: u64, v: u64) -> u64 {
    v
}

/// Whether `/proc/cpuinfo`'s feature list leaves out the word `w`: nothing is hidden on x86_64.
#[inline(always)]
pub fn feature_hidden(_w: &[u8]) -> bool {
    false
}

/// The number of words `Frame::regs_for_record` gives.
pub const RECORD_WORDS: usize = 18;

/// x86_64 kernel `ucontext` as delivered on the alternate stack.
#[repr(C)]
pub struct Frame {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub ss_sp: u64,
    pub ss_flags: u32,
    pub _pad: u32,
    pub ss_size: u64,
    /// r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp rip eflags csgsfs err trapno oldmask cr2
    pub gregs: [u64; 23],
    pub fpstate: u64,
    pub reserved: [u64; 8],
    pub sigmask: u64,
}

#[allow(dead_code)]
pub mod reg {
    pub const R8: usize = 0;
    pub const R9: usize = 1;
    pub const R10: usize = 2;
    pub const R11: usize = 3;
    pub const RDI: usize = 8;
    pub const RSI: usize = 9;
    pub const RBP: usize = 10;
    pub const RBX: usize = 11;
    pub const RDX: usize = 12;
    pub const RAX: usize = 13;
    pub const RCX: usize = 14;
    pub const RSP: usize = 15;
    pub const RIP: usize = 16;
    pub const EFL: usize = 17;
    pub const CSGSFS: usize = 18;
    pub const ERR: usize = 19;
    pub const TRAPNO: usize = 20;
    pub const OLDMASK: usize = 21;
    pub const CR2: usize = 22;
}

use reg::*;

/// Page-fault error code bit: the access was a store.
const PF_WRITE: u64 = 2;

impl Frame {
    /// The interrupted instruction pointer (after the call for SIGSYS, at the instruction for
    /// a fault).
    #[inline(always)]
    pub fn pc(&self) -> u64 {
        self.gregs[RIP]
    }
    #[inline(always)]
    pub fn set_pc(&mut self, v: u64) {
        self.gregs[RIP] = v;
    }
    #[inline(always)]
    pub fn sp(&self) -> u64 {
        self.gregs[RSP]
    }
    #[inline(always)]
    pub fn set_sp(&mut self, v: u64) {
        self.gregs[RSP] = v;
    }
    /// The system-call number of a SIGSYS frame.
    #[inline(always)]
    pub fn nr(&self) -> u64 {
        self.gregs[RAX]
    }
    /// The six arguments of a SIGSYS frame.
    #[inline(always)]
    pub fn args(&self) -> [u64; 6] {
        let g = &self.gregs;
        [g[RDI], g[RSI], g[RDX], g[R10], g[R8], g[R9]]
    }
    /// The result register.
    #[inline(always)]
    pub fn ret(&self) -> i64 {
        self.gregs[RAX] as i64
    }
    #[inline(always)]
    pub fn set_ret(&mut self, r: i64) {
        self.gregs[RAX] = r as u64;
    }
    /// Re-execute the system call `nr` when the frame is returned to.
    #[inline(always)]
    pub fn rewind(&mut self, nr: u64) {
        self.gregs[RAX] = nr;
        self.gregs[RIP] -= SYSCALL_LEN;
    }
    /// Re-execute the call `nr` after a result was written (`sys::sig`'s restarts): the
    /// result register is not an argument here, so this is `rewind`.
    #[inline(always)]
    pub fn restart_after_result(&mut self, nr: u64, _arg0: u64) {
        self.rewind(nr);
    }
    /// The words a preempt record hashes: the general registers, without the trap and resume
    /// flags a spin probe's single steps may leave (in the flags and in the copy `syscall`
    /// saved in r11), which depend on when the probe came.
    pub fn regs_for_record(&self) -> [u64; RECORD_WORDS] {
        let mut words = [0u64; RECORD_WORDS];
        words.copy_from_slice(&self.gregs[..18]);
        const TF_RF: u64 = 0x100 | 0x1_0000;
        words[EFL] &= !TF_RF;
        words[R11] &= !TF_RF;
        words
    }
    /// Whether the fault of this frame was a store.
    #[inline(always)]
    pub fn fault_is_store(&self) -> bool {
        self.gregs[ERR] & PF_WRITE != 0
    }
}
