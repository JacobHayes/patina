//! Process entry on the start-up stack, the signal restorer, and the jumps between stacks.

use core::arch::global_asm;

global_asm!(
    ".section .text.entry,\"ax\"",
    ".globl _start",
    "_start:",
    // Continue on the start-up stack in `.bss` until the first alternate stack exists: the
    // syscall stub accepts only a stack in the runtime's region (`raw.rs`).
    "  mov x0, sp",
    "  adrp x1, patina_boot_stack_top",
    "  add x1, x1, :lo12:patina_boot_stack_top",
    "  mov sp, x1",
    "  bl {start}",
    "  udf #0",
    ".pushsection .bss.patina_boot_stack,\"aw\",@nobits",
    ".balign 16",
    "  .skip 65536",
    "patina_boot_stack_top:",
    ".popsection",
    ".text",
    // The restorer: `rt_sigreturn` through the stub.
    // Preceded by an instruction of its own, so that no call's return address is the
    // restorer: a debugger takes a frame whose pc is the restorer for the runtime's signal
    // frame (the helper's unwinder, `debug/patina-gdb.py`), and a noreturn call ending the
    // function laid out before it would otherwise return there.
    "  udf #0",
    ".globl patina_restorer",
    "patina_restorer:",
    "  mov x8, #{rt_sigreturn}",
    "  b patina_syscall",
    // switch_stack(top, ksp, f): run f(ksp) on a new stack
    ".globl patina_switch_stack",
    "patina_switch_stack:",
    "  mov sp, x0",
    "  mov x0, x1",
    "  blr x2",
    "  udf #0",
    // enter_guest(sp, entry): clean registers and flags, jump (x17 keeps the entry address)
    ".globl patina_enter_guest",
    "patina_enter_guest:",
    "  mov sp, x0",
    "  mov x17, x1",
    "  mov x0, xzr", "mov x1, xzr", "mov x2, xzr", "mov x3, xzr", "mov x4, xzr",
    "  mov x5, xzr", "mov x6, xzr", "mov x7, xzr", "mov x8, xzr", "mov x9, xzr",
    "  mov x10, xzr", "mov x11, xzr", "mov x12, xzr", "mov x13, xzr", "mov x14, xzr",
    "  mov x15, xzr", "mov x16, xzr", "mov x18, xzr", "mov x19, xzr", "mov x20, xzr",
    "  mov x21, xzr", "mov x22, xzr", "mov x23, xzr", "mov x24, xzr", "mov x25, xzr",
    "  mov x26, xzr", "mov x27, xzr", "mov x28, xzr", "mov x29, xzr", "mov x30, xzr",
    "  msr nzcv, xzr",
    "  br x17",
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

/// Enter program code at `entry` with the stack pointer `sp` and every other general
/// register 0 (`x17` holds the entry address).
pub fn enter_guest(sp: u64, entry: u64) -> ! {
    unsafe { patina_enter_guest(sp, entry) }
}
