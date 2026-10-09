//! Capture syscall's raw machine words before entering a fixed Rust ABI.
//! Registers/stack slots are machine values, not a fictitious six-item VaList.
use core::ffi::c_long;

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.text
.globl syscall
.type syscall,@function
.p2align 4
syscall:
  .cfi_startproc
  endbr64
  cmpl $15, %edi
  je 1f
  movq 8(%rsp), %rax
  subq $56, %rsp
  .cfi_def_cfa_offset 64
  movq %rsi, 0(%rsp)
  movq %rdx, 8(%rsp)
  movq %rcx, 16(%rsp)
  movq %r8, 24(%rsp)
  movq %r9, 32(%rsp)
  movq %rax, 40(%rsp)
  movq %rsp, %rsi
  leaq 64(%rsp), %rdx
  call patina_libc_syscall_door
  addq $56, %rsp
  .cfi_def_cfa_offset 8
  ret
  .cfi_endproc
1:
  movq %rsp, %rdi
  andq $-16, %rsp
  pushq %rdi
  pushq %rdi
  call patina_guest_sigreturn
  popq %rsp
  movl $15, %edi
  jmpq *%rax
.size syscall, .-syscall
"#,
    options(att_syntax)
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
.text
.globl syscall
.type syscall,%function
.p2align 2
syscall:
  .cfi_startproc
  bti c
  cmp w0, #139
  b.eq 1f
  sub sp, sp, #64
  .cfi_def_cfa_offset 64
  stp x1, x2, [sp]
  stp x3, x4, [sp, #16]
  stp x5, x6, [sp, #32]
  str x30, [sp, #48]
  .cfi_offset 30, -16
  mov x1, sp
  add x2, sp, #64
  bl patina_libc_syscall_door
  ldr x30, [sp, #48]
  .cfi_restore 30
  add sp, sp, #64
  .cfi_def_cfa_offset 0
  ret
  .cfi_endproc
1:
  mov x0, sp
  sub sp, sp, #16
  str x0, [sp]
  bl patina_guest_sigreturn
  ldr x1, [sp]
  mov sp, x1
  mov x16, x0
  mov x0, #139
  br x16
.size syscall, .-syscall
"#
);

/// # Safety
/// `words` is the six-word initialized capture made by the architecture entry.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_libc_syscall_fixed(
    number: c_long,
    words: *const [u64; 6],
) -> c_long {
    // Charged as the call it makes, as the trap for the raw instruction is.
    let _panic_scope = crate::panic_boundary::PanicScope::enter_syscall(number);
    let mutated = super::fault(8);
    // SAFETY: both assembly producers store every word in aligned live storage.
    let mut args = unsafe { *words };
    if mutated {
        args[0] = args[1];
    }
    // SAFETY: each registry handler interprets only the operands of its syscall.
    super::raw_result(unsafe {
        crate::sud::patina_sud_dispatch(
            number, args[0], args[1], args[2], args[3], args[4], args[5], 0,
        )
    })
}

unsafe extern "C" {
    fn patina_signal_return(mask_address: usize) -> usize;
}
core::arch::global_asm!(
    ".hidden patina_libc_syscall_fixed",
    ".hidden patina_guest_sigreturn",
);

/// Locate the guest frame's signal mask, then return the private host vehicle.
#[unsafe(no_mangle)]
pub extern "C" fn patina_guest_sigreturn(sp: usize) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_arch = "aarch64")]
    let sp = sp.wrapping_add(core::mem::size_of::<libc::siginfo_t>());
    let mask = sp.wrapping_add(core::mem::offset_of!(libc::ucontext_t, uc_sigmask));
    // SAFETY: the existing signal-return model validates/copies the guest frame.
    unsafe { patina_signal_return(mask) }
}
