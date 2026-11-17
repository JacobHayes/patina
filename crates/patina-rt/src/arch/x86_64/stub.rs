//! The runtime's one `syscall` instruction (`raw.rs` has the containment argument).

use core::arch::{asm, global_asm};
use proto::layout::{RT_REGION_SHIFT, RT_REGION_TAG};

global_asm!(
    ".globl patina_syscall",
    "patina_syscall:",
    "  syscall",
    "  mov rcx, rsp",
    "  shr rcx, {shift}",
    "  cmp rcx, {tag}",
    "  jne patina_syscall_escape",
    "  ret",
    ".globl patina_syscall_escape",
    "patina_syscall_escape:",
    "  ud2",
    shift = const RT_REGION_SHIFT,
    tag = const RT_REGION_TAG,
);

extern "C" {
    fn patina_syscall();
    fn patina_syscall_escape();
}

/// The address the kernel reports for a call from the stub (after its `syscall`).
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
    // `call` pushes below the stack pointer: the target has no red zone to clobber.
    asm!("call {stub}", stub = sym patina_syscall, inlateout("rax") n as i64 => r,
         in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e, in("r9") f,
         lateout("rcx") _, lateout("r11") _);
    r
}
