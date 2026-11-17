//! The clone and sigreturn trampolines, and the extent of a trap frame (`sys::thread`'s
//! `copy_frame`).

use super::Frame;

core::arch::global_asm!(
    // patina_clone_vm(flags, stack, ptid, ctid, tls, uc2): the real clone, through the syscall
    // stub. The child starts on `stack` (inside its own alternate stack), where the stub's `ret`
    // finds `patina_clone_child` and then `uc2`; it calls thread_start(uc2) and never returns
    // here or touches the parent's stacks. The parent returns from the stub to the caller.
    ".globl patina_clone_vm",
    "patina_clone_vm:",
    "  lea rax, [rip + patina_clone_child]",
    "  mov [rsi - 16], rax",
    "  mov [rsi - 8], r9",
    "  sub rsi, 16",
    "  mov r10, rcx",
    "  mov eax, {clone}",
    "  jmp patina_syscall",
    "patina_clone_child:",
    "  pop rdi",
    "  and rsp, -16",
    "  call {start}",
    "  ud2",
    // patina_sigreturn_to(uc): rt_sigreturn with the frame at `uc`.
    ".globl patina_sigreturn_to",
    "patina_sigreturn_to:",
    "  mov rsp, rdi",
    "  mov eax, {rt_sigreturn}",
    "  jmp patina_syscall",
    start = sym crate::sys::thread::thread_start,
    clone = const crate::raw::nr::CLONE,
    rt_sigreturn = const crate::raw::nr::RT_SIGRETURN,
);

extern "C" {
    fn patina_clone_vm(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64, uc2: u64) -> i64;
    fn patina_sigreturn_to(uc: u64) -> !;
}

/// The real `clone` with `CLONE_VM`: the child starts in `sys::thread::thread_start(uc2)` on
/// `stack`; the parent gets the tid or -errno.
pub fn clone_vm(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64, uc2: u64) -> i64 {
    unsafe { patina_clone_vm(flags, stack, ptid, ctid, tls, uc2) }
}

/// Enter guest code with the frame at `uc` (`rt_sigreturn`).
pub fn sigreturn_to(uc: u64) -> ! {
    unsafe { patina_sigreturn_to(uc) }
}

/// The lowest byte of the kernel's signal frame whose ucontext is at `uc`: the restorer's
/// return-address slot below it. The frame runs from there to the top of the alternate stack.
#[inline(always)]
pub fn frame_extent(uc: u64) -> u64 {
    uc - 8
}

/// Fix the pointers inside a frame copied `delta` bytes up: the FP-state pointer.
pub fn rebase_frame(f: &mut Frame, delta: u64) {
    if f.fpstate != 0 {
        f.fpstate += delta;
    }
}
