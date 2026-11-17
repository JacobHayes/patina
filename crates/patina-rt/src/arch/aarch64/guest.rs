//! The guest copy: a byte loop whose load and store the fault entry recognises by address and
//! turns into a return of `-EFAULT` (`crate::guest` has the rules).

core::arch::global_asm!(
    ".pushsection .text.patina_guest_copy,\"ax\",@progbits",
    ".globl patina_guest_copy",
    "patina_guest_copy:",
    "  cbz x2, 2f",
    "1:",
    ".globl patina_guest_copy_ld",
    "patina_guest_copy_ld:",
    "  ldrb w3, [x1], #1",
    ".globl patina_guest_copy_st",
    "patina_guest_copy_st:",
    "  strb w3, [x0], #1",
    "  subs x2, x2, #1",
    "  b.ne 1b",
    "2:",
    "  mov x0, xzr",
    "  ret",
    ".globl patina_guest_copy_fixup",
    "patina_guest_copy_fixup:",
    "  mov x0, #-14",
    "  ret",
    ".popsection",
);

extern "C" {
    fn patina_guest_copy(dst: *mut u8, src: *const u8, n: usize) -> i64;
    fn patina_guest_copy_ld();
    fn patina_guest_copy_st();
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
    let ld = patina_guest_copy_ld as *const () as u64;
    let st = patina_guest_copy_st as *const () as u64;
    (pc == ld || pc == st).then_some(patina_guest_copy_fixup as *const () as u64)
}

/// The stack pointer of the caller.
#[inline(always)]
pub fn current_sp() -> u64 {
    let sp: u64;
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    sp
}
