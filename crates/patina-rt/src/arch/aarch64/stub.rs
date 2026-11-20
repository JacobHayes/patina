//! The runtime's one `svc` instruction (`raw.rs` has the containment argument). `ret` returns
//! through `x30`, not the stack; the check after the call reads only `sp`. The counter overflow
//! entry sits right before it and falls through into it (`crate::pmu`).

use core::arch::{asm, global_asm};
use proto::layout::{RT_REGION_SHIFT, RT_REGION_TAG};

global_asm!(
    // The counter overflow entry (`crate::pmu`, registered for SIGTRAP with counter preemption
    // on; x0 = signal, x1 = siginfo, x2 = ucontext, x30 = the restorer, on the alternate stack).
    // It reads the counter into `ra` with no branch before the read: it falls through into the
    // `svc` below with x30 set to `2:`, so the guest's count does not depend on whether the
    // counter ran before the read. Any other SIGTRAP reads descriptor -1 (it fails at once)
    // and goes on to the plain path.
    ".globl patina_sigtrap",
    "patina_sigtrap:",
    "  stp x29, x30, [sp, #-32]!",
    "  stp x1, x2, [sp, #16]",
    "  ldr w9, [x1, #8]", // si_code
    "  mov x10, sp",
    "  and x10, x10, #{altmask}",
    "  ldr x0, [x10, #{off_fd}]",
    "  mov x11, #-1",
    "  cmp w9, #6", // TRAP_PERF
    "  csel x0, x0, x11, eq",
    "  add x1, x10, #{off_ra}",
    "  str x11, [x1]",
    "  mov x2, #8",
    "  mov x8, #{read}",
    "  adr x30, 2f",
    ".globl patina_syscall",
    "patina_syscall:",
    "  svc #0",
    "  mov x16, sp",
    "  lsr x16, x16, #{shift}",
    "  cmp x16, #{tag}",
    "  b.ne patina_syscall_escape",
    "  ret",
    ".globl patina_syscall_escape",
    "patina_syscall_escape:",
    "  udf #0",
    "2:",
    "  ldp x0, x1, [sp, #16]",
    "  ldr w9, [x0, #8]",
    "  cmp w9, #6",
    "  b.ne 8f",
    "  bl {alarm}",
    "  ldp x29, x30, [sp], #32",
    "  ret",
    "8:",
    "  mov x2, x1",
    "  mov x1, x0",
    "  mov w0, #5", // SIGTRAP
    "  ldp x29, x30, [sp], #32",
    "  b {plain}",
    shift = const RT_REGION_SHIFT,
    tag = const RT_REGION_TAG,
    altmask = const !(proto::layout::ALT_SIZE - 1),
    off_fd = const crate::pmu::OFF_FD,
    off_ra = const crate::pmu::OFF_RA,
    read = const crate::raw::nr::READ,
    alarm = sym crate::pmu::alarm,
    plain = sym crate::pmu::trap_plain,
);

extern "C" {
    fn patina_syscall();
    fn patina_syscall_escape();
}

/// The address the kernel reports for a call from the stub (after its `svc`).
pub fn stub_ip() -> u64 {
    patina_syscall as *const () as u64 + super::SYSCALL_LEN
}

/// The stub's stop for a call made from a program's stack.
pub fn stub_escape() -> u64 {
    patina_syscall_escape as *const () as u64
}

#[inline(always)]
pub unsafe fn sc6(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
    let r: i64;
    // `bl` writes the return address to x30; the stub uses x16 and the flags.
    asm!("bl {stub}", stub = sym patina_syscall, in("x8") n,
         inlateout("x0") a as i64 => r, in("x1") b, in("x2") c, in("x3") d, in("x4") e,
         in("x5") f, lateout("x16") _, lateout("x30") _);
    r
}
