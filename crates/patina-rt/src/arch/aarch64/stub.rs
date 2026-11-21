//! The runtime's one `svc` instruction (`raw.rs` has the containment argument). `ret` returns
//! through `x30`, not the stack; the check after the call reads only `sp`.

use core::arch::{asm, global_asm};
use proto::layout::{RT_REGION_SHIFT, RT_REGION_TAG};

global_asm!(
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
    shift = const RT_REGION_SHIFT,
    tag = const RT_REGION_TAG,
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
