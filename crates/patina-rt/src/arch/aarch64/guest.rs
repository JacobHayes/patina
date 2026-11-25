//! The guest copy: a 16-byte / 8-byte / 1-byte loop whose loads and stores the fault entry
//! recognises by address range and turns into a return of `-EFAULT` (`crate::guest` has the rules).

core::arch::global_asm!(
    ".pushsection .text.patina_guest_copy,\"ax\",@progbits",
    ".globl patina_guest_copy",
    "patina_guest_copy:",
    "  cmp x2, #16",
    "  b.lo 2f",
    ".globl patina_guest_copy_fault_start",
    "patina_guest_copy_fault_start:",
    "1:",
    "  ldp x3, x4, [x1], #16",
    "  stp x3, x4, [x0], #16",
    "  sub x2, x2, #16",
    "  cmp x2, #16",
    "  b.hs 1b",
    "2:",
    "  tbz x2, #3, 3f",
    "  ldr x3, [x1], #8",
    "  str x3, [x0], #8",
    "  sub x2, x2, #8",
    "3:",
    "  cbz x2, 5f",
    "4:",
    "  ldrb w3, [x1], #1",
    "  strb w3, [x0], #1",
    "  subs x2, x2, #1",
    "  b.ne 4b",
    ".globl patina_guest_copy_fault_end",
    "patina_guest_copy_fault_end:",
    "5:",
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
    fn patina_guest_copy_fault_start();
    fn patina_guest_copy_fault_end();
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
    let start = patina_guest_copy_fault_start as *const () as u64;
    let end = patina_guest_copy_fault_end as *const () as u64;
    (start..end)
        .contains(&pc)
        .then_some(patina_guest_copy_fixup as *const () as u64)
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
