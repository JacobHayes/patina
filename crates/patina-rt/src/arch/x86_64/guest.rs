//! The guest copy: one `rep movsb` whose fault the fault entry turns into `-EFAULT`
//! (`crate::guest` has the rules).

core::arch::global_asm!(
    ".pushsection .text.patina_guest_copy,\"ax\",@progbits",
    ".globl patina_guest_copy",
    "patina_guest_copy:",
    "mov rcx, rdx",
    ".globl patina_guest_copy_insn",
    "patina_guest_copy_insn:",
    "rep movsb",
    "xor eax, eax",
    "ret",
    ".globl patina_guest_copy_fixup",
    "patina_guest_copy_fixup:",
    "mov rax, -14",
    "ret",
    ".popsection",
);

extern "C" {
    fn patina_guest_copy(dst: *mut u8, src: *const u8, n: usize) -> i64;
    fn patina_guest_copy_insn();
    fn patina_guest_copy_fixup();
}

/// Copy `n` bytes: 0, or `-EFAULT` if an access faulted.
#[inline(always)]
pub unsafe fn guest_copy(dst: *mut u8, src: *const u8, n: usize) -> i64 {
    patina_guest_copy(dst, src, n)
}

/// Called by the fault handler for a fault at `pc` in runtime text: where to resume, if the
/// fault was a guest copy's.
pub fn fixup(pc: u64) -> Option<u64> {
    let insn = patina_guest_copy_insn as *const () as u64;
    (pc == insn).then_some(patina_guest_copy_fixup as *const () as u64)
}

/// The stack pointer of the caller.
#[inline(always)]
pub fn current_sp() -> u64 {
    let sp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    sp
}
