// Jumps the rewriter cannot see into the interior of group patches (tests/rewrite/04-interior).
// Each routine below is a loop or a run of instructions too short for a count of its own, so
// the rewriter merges it with its neighbours into a group patch; the global labels e_* (not
// function symbols: the rewriter sees no branch to them) are exactly the starts of the
// instructions inside those groups. A table in read-only data, which the rewriter does not
// follow, names every routine's start and every label twice, each with its own arguments, and the
// dispatcher enters them by `call`, by `jmp` with a pushed return address and by `ret`. It
// prints a checksum of the results and the number of entries made. With an argument it then
// maps over the 64 MiB after its image (`MAP_FIXED`) and makes every entry again. Natively,
// under the rewritten copy (without an argument: its trampolines are in that range) and under
// Patina the output is the same. No C library: x86_64 Linux system calls only, so the only
// groups in the file are these.

    .text

// eax += edi, esi times. Two-byte instructions: the group is the last three, and its jump
// needs a prefix (a boundary at offset 4).
    .globl r_add
    .type r_add, @function
r_add:
    xor %eax, %eax
1:  add %edi, %eax
    .globl e_add_dec
e_add_dec:
    dec %esi
    .globl e_add_jnz
e_add_jnz:
    jnz 1b
    ret
    .size r_add, . - r_add

// One-byte instructions: interior boundaries at offsets 1, 2 and 3 of the patch, the low
// three bytes of its jump's displacement.
    .globl r_one
    .type r_one, @function
r_one:
    mov %edi, %eax
1:  add %ecx, %eax
    dec %esi
    jz 2f
    xchg %eax, %ecx
    .globl e_one_cltd
e_one_cltd:
    cltd
    .globl e_one_xchg
e_one_xchg:
    xchg %eax, %edx
    .globl e_one_jmp
e_one_jmp:
    jmp 1b
2:  ret
    .size r_one, . - r_one

// A group that ends before the branch: the instruction that sets the flags and the one after
// it (the branch, outside the group, is a dark entry too).
    .globl r_fill
    .type r_fill, @function
r_fill:
    xor %eax, %eax
1:  sub $1, %esi
    .globl e_fill_lea
e_fill_lea:
    lea 3(%rax,%rdi), %eax
    .globl d_fill_jnz
d_fill_jnz:
    jnz 1b
    ret
    .size r_fill, . - r_fill

// A loop whose back-edge block is too short (a forward branch lands in it): the group is the
// run at the loop head, which ends in that forward branch.
    .globl r_head
    .type r_head, @function
r_head:
    xor %eax, %eax
1:  add %edi, %eax
    .globl e_head_test
e_head_test:
    test $1, %al
    .globl e_head_jz
e_head_jz:
    jz 2f
    inc %eax
2:  dec %esi
    jnz 1b
    ret
    .size r_head, . - r_head

// An atomic with no room for a count: the group is the straight-line run after it. d_* labels
// are dark entries that are not inside a group (a group's start, an instruction outside one).
    .globl r_atomic
    .type r_atomic, @function
r_atomic:
    mov %esi, %eax
    lock incl (%rdi)
    .globl d_atomic_mov
d_atomic_mov:
    mov %eax, %ecx
    .globl d_atomic_shl
d_atomic_shl:
    shl $1, %ecx
    .globl e_atomic_lea
e_atomic_lea:
    lea (%rcx,%rax), %eax
    ret
    .size r_atomic, . - r_atomic

// A RIP-relative load between the instruction that sets the flags and the branch that reads
// them (no place for a count before the load): the copy of the load has its own displacement.
    .globl r_rip
    .type r_rip, @function
r_rip:
    xor %ecx, %ecx
    xor %eax, %eax
1:  add %ecx, %eax
    .globl d_rip_sub
d_rip_sub:
    sub $1, %esi
    .globl e_rip_mov
e_rip_mov:
    mov k_step(%rip), %ecx
    .globl d_rip_jnz
d_rip_jnz:
    jnz 1b
    add %edi, %eax
    ret
    .size r_rip, . - r_rip

// A group across a page boundary (its interior boundary is the page's first byte).
    .p2align 12
    .skip 4096 - 9, 0x90
    .globl r_page
    .type r_page, @function
r_page:
    xor %eax, %eax
    nop
    nop
    nop
    nop
    nop
1:  add %edi, %eax
    .globl e_page_dec
e_page_dec:
    dec %esi
    .globl e_page_jnz
e_page_jnz:
    jnz 1b
    ret
    .size r_page, . - r_page

// The dispatcher: for each row (address, rdi, rsi), enter the address with rdi and rsi, the
// row's index in rax, rdx and (its low two bits) rcx, no other register naming an address
// the program's other routines read, and the flags of `test %esi, %esi` (a nonzero count: the routines' branches go back), by the
// row's way, fold eax into r12, and make a system call.
    .globl _start
    .type _start, @function
_start:
    // With an argument, a second pass after mapping over the 64 MiB past the image (where the
    // trampolines are under load-time points; free natively).
    mov (%rsp), %r15
    xor %r12d, %r12d
    xor %r13d, %r13d
1:  lea rows(%rip), %rbx
    lea rows_end(%rip), %r14
2:  cmp %r14, %rbx
    jae 9f
    mov (%rbx), %r11
    lea rows(%rip), %rcx
    add %rcx, %r11
    mov 8(%rbx), %rdi
    mov 16(%rbx), %rsi
    cmp $0, %rdi
    jne 3f
    lea cell(%rip), %rdi
3:  mov %r13, %rdx
    mov %r13, %rax
    add $1, %r13
    mov %edx, %ecx
    and $3, %ecx
    cmp $1, %ecx
    je 4f
    cmp $2, %ecx
    je 5f
    test %esi, %esi
    call *%r11
    jmp 6f
4:  lea 6f(%rip), %r10
    push %r10
    test %esi, %esi
    jmp *%r11
5:  lea 6f(%rip), %r10
    push %r10
    push %r11
    test %esi, %esi
    ret
    // getppid between entries: the program is one thread, so under load-time points a point
    // is taken only at the first count after a system call (ARCHITECTURE "Compute points").
6:  mov %eax, %r8d
    mov $110, %eax
    syscall
    imul $1000003, %r12, %r12
    mov %r8d, %eax
    add %rax, %r12
    add $24, %rbx
    jmp 2b
9:  cmp $2, %r15
    jb 0f
    xor %r15d, %r15d
    lea _end+4095(%rip), %rdi
    and $-4096, %rdi
    mov $64 << 20, %esi
    mov $3, %edx            // PROT_READ | PROT_WRITE
    mov $0x32, %r10d        // MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    jmp 1b
0:  // "<checksum in hex> <entries in decimal>\n"
    lea buf+16(%rip), %rdi
    mov $16, %ecx
7:  mov %r12, %rax
    and $15, %eax
    lea hex(%rip), %rdx
    movzbl (%rdx,%rax), %eax
    dec %rdi
    mov %al, (%rdi)
    shr $4, %r12
    dec %ecx
    jnz 7b
    movb $' ', buf+16(%rip)
    lea buf+40(%rip), %rdi
    movb $'\n', (%rdi)
    mov %r13, %rax
    mov $10, %ecx
8:  mov $0, %edx
    div %rcx
    add $'0', %dl
    dec %rdi
    mov %dl, (%rdi)
    test %rax, %rax
    jnz 8b
    // buf: 16 hex digits and a space; then the digits at rdi up to the newline at buf+40.
    lea buf(%rip), %rsi
    mov $17, %edx
    mov %rdi, %r15
    mov $1, %edi
    mov $1, %eax
    syscall
    mov %r15, %rsi
    lea buf+41(%rip), %rdx
    sub %r15, %rdx
    mov $1, %edi
    mov $1, %eax
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
    .size _start, . - _start

    .section .rodata
k_step:
    .long 7
hex:
    .ascii "0123456789abcdef"
    .p2align 3
// rdi 0: the address of `cell` (r_atomic's memory).
// Addresses as offsets from `rows`: no relocation names them (a static-PIE build has none).
#define ROW2(a, d1, s1, d2, s2) .quad a - rows, d1, s1; .quad a - rows, d2, s2
rows:
    ROW2(r_add, 3, 5, 11, 2)
    ROW2(e_add_dec, 7, 4, 2, 1)
    ROW2(e_add_jnz, 5, 3, 9, 6)
    ROW2(r_one, 3, 4, 100, 2)
    ROW2(e_one_cltd, 6, 3, 13, 1)
    ROW2(e_one_xchg, 5, 2, 17, 3)
    ROW2(e_one_jmp, 4, 5, 8, 2)
    ROW2(r_fill, 3, 6, 4, 3)
    ROW2(e_fill_lea, 9, 3, 21, 1)
    ROW2(d_fill_jnz, 2, 4, 30, 2)
    ROW2(r_head, 3, 6, 4, 3)
    ROW2(e_head_test, 5, 4, 2, 2)
    ROW2(e_head_jz, 7, 5, 6, 3)
    ROW2(r_atomic, 0, 5, 0, 9)
    ROW2(d_atomic_mov, 0, 3, 0, 4)
    ROW2(d_atomic_shl, 0, 6, 0, 2)
    ROW2(e_atomic_lea, 0, 8, 0, 1)
    ROW2(r_rip, 3, 6, 5, 2)
    ROW2(d_rip_sub, 4, 5, 6, 3)
    ROW2(e_rip_mov, 2, 4, 8, 1)
    ROW2(d_rip_jnz, 6, 2, 1, 5)
    ROW2(r_page, 3, 5, 6, 2)
    ROW2(e_page_dec, 7, 4, 2, 1)
    ROW2(e_page_jnz, 5, 3, 9, 6)
rows_end:

    .bss
cell:
    .quad 0
buf:
    .skip 48

    .section .note.GNU-stack, "", @progbits
