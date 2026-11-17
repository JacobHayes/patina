//! Process entry on the start-up stack, the signal restorer, and the jumps between stacks.

use core::arch::global_asm;

global_asm!(
    ".section .text.entry,\"ax\"",
    ".globl _start",
    "_start:",
    // Continue on the start-up stack in `.bss` until the first alternate stack exists: the
    // syscall stub accepts only a stack in the runtime's region (`raw.rs`).
    "  mov rdi, rsp",
    "  lea rsp, [rip + patina_boot_stack_top]",
    "  call {start}",
    "  ud2",
    ".pushsection .bss.patina_boot_stack,\"aw\",@nobits",
    ".balign 16",
    "  .skip 65536",
    "patina_boot_stack_top:",
    ".popsection",
    ".text",
    ".globl patina_restorer",
    "patina_restorer:",
    "  mov eax, {rt_sigreturn}",
    "  jmp patina_syscall",
    // switch_stack(top, ksp, f): run f(ksp) on a new stack
    ".globl patina_switch_stack",
    "patina_switch_stack:",
    "  mov rsp, rdi",
    "  mov rdi, rsi",
    "  call rdx",
    "  ud2",
    // enter_guest(sp, entry): clean registers, jump
    ".globl patina_enter_guest",
    "patina_enter_guest:",
    "  mov rsp, rdi",
    "  mov rax, rsi",
    "  xor ebx, ebx", "xor ecx, ecx", "xor edx, edx", "xor esi, esi", "xor edi, edi", "xor ebp, ebp",
    "  xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
    "  xor r12d, r12d", "xor r13d, r13d", "xor r14d, r14d", "xor r15d, r15d",
    "  jmp rax",
    start = sym crate::entry::rt_start,
    rt_sigreturn = const crate::raw::nr::RT_SIGRETURN,
);

extern "C" {
    fn patina_restorer();
    fn patina_switch_stack(top: u64, ksp: u64, f: extern "C" fn(u64) -> !) -> !;
    fn patina_enter_guest(sp: u64, entry: u64) -> !;
}

/// The runtime's signal restorer (`SA_RESTORER`): `rt_sigreturn` through the stub.
pub fn restorer() -> u64 {
    patina_restorer as *const () as u64
}

/// Run `f(ksp)` on the stack whose top is `top`.
pub fn switch_stack(top: u64, ksp: u64, f: extern "C" fn(u64) -> !) -> ! {
    unsafe { patina_switch_stack(top, ksp, f) }
}

/// Enter program code at `entry` with the stack pointer `sp` and every other register 0.
pub fn enter_guest(sp: u64, entry: u64) -> ! {
    unsafe { patina_enter_guest(sp, entry) }
}
