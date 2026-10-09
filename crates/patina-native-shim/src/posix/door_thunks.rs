//! The C exits of the libc doors that forward to the syscall model
//! (`sud::forward`). Each public symbol is a thunk that holds the thread for
//! the door the way a trap handler does, calls the Rust door (exported as
//! `patina_door_<name>`) with the caller's argument registers, and then runs
//! the door's exit (`patina_door_exit`, `c/posix/delivery.c`): what the call
//! made deliverable is delivered there, with every Rust frame returned, and a
//! call `SA_RESTART` restarts runs again from the same registers. The thunk
//! keeps no state but its own frame and moves no stack argument, so it fits
//! doors whose arguments all travel in registers: these all do (at most six
//! integer words).
//!
//! A door listed here with no `patina_door_<name>` definition is an undefined
//! reference at link time, and one still exported under its public name a
//! duplicate definition.

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.macro PATINA_DOOR name
.text
.globl \name
.type \name,@function
.p2align 4
\name:
  .cfi_startproc
  endbr64
  pushq %rbp
  .cfi_def_cfa_offset 16
  .cfi_offset %rbp, -16
  movq %rsp, %rbp
  .cfi_def_cfa_register %rbp
  subq $64, %rsp
  movq %rdi, -8(%rbp)
  movq %rsi, -16(%rbp)
  movq %rdx, -24(%rbp)
  movq %rcx, -32(%rbp)
  movq %r8, -40(%rbp)
  movq %r9, -48(%rbp)
  leaq 16(%rbp), %rdi
  call patina_door_hold
1:
  movq -8(%rbp), %rdi
  movq -16(%rbp), %rsi
  movq -24(%rbp), %rdx
  movq -32(%rbp), %rcx
  movq -40(%rbp), %r8
  movq -48(%rbp), %r9
  call patina_door_\name
  movq %rax, -56(%rbp)
  call patina_door_exit
  testl %eax, %eax
  jnz 1b
  movq -56(%rbp), %rax
  leave
  .cfi_def_cfa %rsp, 8
  ret
  .cfi_endproc
.size \name, .-\name
.endm
PATINA_DOOR acct
PATINA_DOOR chroot
PATINA_DOOR delete_module
PATINA_DOOR fsconfig
PATINA_DOOR fsmount
PATINA_DOOR fsopen
PATINA_DOOR fspick
PATINA_DOOR gethostname
PATINA_DOOR getrusage
PATINA_DOOR init_module
PATINA_DOOR ioperm
PATINA_DOOR iopl
PATINA_DOOR kill
PATINA_DOOR killpg
PATINA_DOOR mount
PATINA_DOOR mount_setattr
PATINA_DOOR move_mount
PATINA_DOOR open_tree
PATINA_DOOR pidfd_getfd
PATINA_DOOR pidfd_open
PATINA_DOOR pidfd_send_signal
PATINA_DOOR pivot_root
PATINA_DOOR process_madvise
PATINA_DOOR process_mrelease
PATINA_DOOR process_vm_readv
PATINA_DOOR process_vm_writev
PATINA_DOOR quotactl
PATINA_DOOR raise
PATINA_DOOR reboot
PATINA_DOOR sched_getaffinity
PATINA_DOOR sched_setaffinity
PATINA_DOOR setgid
PATINA_DOOR setgroups
PATINA_DOOR setns
PATINA_DOOR setpgid
PATINA_DOOR setsid
PATINA_DOOR setuid
PATINA_DOOR sigqueue
PATINA_DOOR swapoff
PATINA_DOOR swapon
PATINA_DOOR sysinfo
PATINA_DOOR tgkill
PATINA_DOOR tkill
PATINA_DOOR umount2
PATINA_DOOR uname
PATINA_DOOR unshare
PATINA_DOOR vhangup
PATINA_DOOR waitid
PATINA_DOOR waitpid
.purgem PATINA_DOOR
"#,
    options(att_syntax)
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
.macro PATINA_DOOR name
.text
.globl \name
.type \name,%function
.p2align 2
\name:
  .cfi_startproc
  bti c
  stp x29, x30, [sp, #-80]!
  .cfi_def_cfa_offset 80
  .cfi_offset 29, -80
  .cfi_offset 30, -72
  mov x29, sp
  stp x0, x1, [sp, #16]
  stp x2, x3, [sp, #32]
  stp x4, x5, [sp, #48]
  add x0, sp, #80
  bl patina_door_hold
1:
  ldp x0, x1, [sp, #16]
  ldp x2, x3, [sp, #32]
  ldp x4, x5, [sp, #48]
  bl patina_door_\name
  str x0, [sp, #64]
  bl patina_door_exit
  cbnz w0, 1b
  ldr x0, [sp, #64]
  ldp x29, x30, [sp], #80
  .cfi_def_cfa_offset 0
  .cfi_restore 29
  .cfi_restore 30
  ret
  .cfi_endproc
.size \name, .-\name
.endm
PATINA_DOOR acct
PATINA_DOOR chroot
PATINA_DOOR delete_module
PATINA_DOOR fsconfig
PATINA_DOOR fsmount
PATINA_DOOR fsopen
PATINA_DOOR fspick
PATINA_DOOR gethostname
PATINA_DOOR getrusage
PATINA_DOOR init_module
PATINA_DOOR kill
PATINA_DOOR killpg
PATINA_DOOR mount
PATINA_DOOR mount_setattr
PATINA_DOOR move_mount
PATINA_DOOR open_tree
PATINA_DOOR pidfd_getfd
PATINA_DOOR pidfd_open
PATINA_DOOR pidfd_send_signal
PATINA_DOOR pivot_root
PATINA_DOOR process_madvise
PATINA_DOOR process_mrelease
PATINA_DOOR process_vm_readv
PATINA_DOOR process_vm_writev
PATINA_DOOR quotactl
PATINA_DOOR raise
PATINA_DOOR reboot
PATINA_DOOR sched_getaffinity
PATINA_DOOR sched_setaffinity
PATINA_DOOR setgid
PATINA_DOOR setgroups
PATINA_DOOR setns
PATINA_DOOR setpgid
PATINA_DOOR setsid
PATINA_DOOR setuid
PATINA_DOOR sigqueue
PATINA_DOOR swapoff
PATINA_DOOR swapon
PATINA_DOOR sysinfo
PATINA_DOOR tgkill
PATINA_DOOR tkill
PATINA_DOOR umount2
PATINA_DOOR uname
PATINA_DOOR unshare
PATINA_DOOR vhangup
PATINA_DOOR waitid
PATINA_DOOR waitpid
.purgem PATINA_DOOR
"#
);
