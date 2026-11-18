//! The clone and sigreturn trampolines, and the extent of a trap frame (`sys::thread`'s
//! `copy_frame`).
//!
//! The stub returns through `x30`, not the stack, so the clone trampoline cannot leave the
//! child a return address on its new stack as x86_64 does: it points `x30` at its own label
//! before branching to the stub, and both tasks come back there, told apart by `x0` (0 in
//! the child). The child finds its frame copy in `x19`, a callee-saved register the kernel
//! copies; the parent restores its own `x19` and `x30` and returns.

use super::Frame;

core::arch::global_asm!(
    // patina_clone_vm(flags, stack, ptid, ctid, tls, uc2): the kernel takes (flags, stack,
    // ptid, tls, ctid). The child starts on `stack` (inside its own alternate stack) and calls
    // thread_start(uc2); it never returns here or touches the parent's stacks.
    ".globl patina_clone_vm",
    "patina_clone_vm:",
    "  stp x19, x30, [sp, #-16]!",
    "  mov x19, x5",
    "  mov x5, x3",
    "  mov x3, x4",
    "  mov x4, x5",
    "  mov x8, #{clone}",
    "  adr x30, patina_clone_back",
    "  b patina_syscall",
    "patina_clone_back:",
    "  cbz x0, patina_clone_child",
    "  ldp x19, x30, [sp], #16",
    "  ret",
    "patina_clone_child:",
    "  mov x0, x19",
    "  bl {start}",
    "  udf #0",
    // patina_sigreturn_to(uc): rt_sigreturn with the frame whose ucontext is at `uc` (the
    // kernel reads the frame at `sp`, the siginfo before the ucontext), after the counter
    // read that starts a measured segment (`pmu`'s `patina_sigreturn_read`).
    ".globl patina_sigreturn_to",
    "patina_sigreturn_to:",
    "  sub x0, x0, #{siginfo}",
    "  mov sp, x0",
    "  b patina_sigreturn_read",
    start = sym crate::sys::thread::thread_start,
    clone = const crate::raw::nr::CLONE,
    siginfo = const SIGINFO_SIZE,
);

extern "C" {
    fn patina_clone_vm(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64, uc2: u64) -> i64;
    fn patina_sigreturn_to(uc: u64) -> !;
}

/// `struct rt_sigframe` is the siginfo, then the ucontext.
const SIGINFO_SIZE: u64 = 128;

/// The real `clone` with `CLONE_VM`: the child starts in `sys::thread::thread_start(uc2)` on
/// `stack` (16-byte aligned); the parent gets the tid or -errno.
pub fn clone_vm(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64, uc2: u64) -> i64 {
    unsafe { patina_clone_vm(flags, stack, ptid, ctid, tls, uc2) }
}

/// Enter guest code with the frame at `uc` (`rt_sigreturn`; the copy keeps the frame's 16-byte
/// alignment, which the kernel checks).
pub fn sigreturn_to(uc: u64) -> ! {
    unsafe { patina_sigreturn_to(uc) }
}

/// The lowest byte of the kernel's signal frame whose ucontext is at `uc`: its siginfo. The
/// frame runs from there through the frame record above it to the top of the alternate stack.
#[inline(always)]
pub fn frame_extent(uc: u64) -> u64 {
    uc - SIGINFO_SIZE
}

/// `EXTRA_MAGIC`: a record pointing at more records past the frame's 4 KiB area (a frame too
/// large for it: long SVE vectors, live SME state).
const EXTRA_MAGIC: u32 = 0x4558_5401;

/// Fix the pointers inside a frame copied `delta` bytes up: an `extra_context` record's data
/// pointer, which the kernel requires to point just past the record list (inside the copy).
pub fn rebase_frame(f: &mut Frame, delta: u64) {
    let mut off = 0usize;
    while off + 8 <= f.records.len() {
        let h = &f.records[off..];
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if magic == 0 || size < 8 || off + size > f.records.len() {
            return;
        }
        if magic == EXTRA_MAGIC && size >= 16 {
            let mut d = [0u8; 8];
            d.copy_from_slice(&f.records[off + 8..off + 16]);
            let datap = u64::from_le_bytes(d) + delta;
            f.records[off + 8..off + 16].copy_from_slice(&datap.to_le_bytes());
        }
        off += size;
    }
}
