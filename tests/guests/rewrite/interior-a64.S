// Jumps the rewriter cannot see into and around the sites of its plan, on arm64
// (tests/rewrite/04-interior). arm64 has no group patch: every site is one word that becomes a
// branch to its trampoline, so no address inside a patch exists. What a jump the rewriter cannot
// see can still do is land on a patched word itself, or on the word after it, with registers
// and flags the rewriter never saw. Each routine below is a loop or a call whose site (labels
// s_*, a backward cbnz, b.cond, tbnz and bl, an indirect br, an atomic) and neighbours (labels
// e_*) are entered from a table in read-only data, which the rewriter does not follow, each
// twice with its own arguments, by `blr`, by `br` with the return address in x30 and by `ret`.
// It prints a checksum of the results and the number of entries made. With an argument it then
// maps over the 64 MiB after its image (`MAP_FIXED`) and makes every entry again. Natively,
// under the rewritten copy (without an argument) and under Patina the output is the same. No C
// library: arm64 Linux system calls only.
//
// Every entry gets: w0, w1 the row's arguments (w1 at least 1), w2 = 1 + (index & 3), x3 the
// index, x4 the address of `cell`, x8 the return address (also in x30), x9 the address of
// r_land, and the flags of `cmp w1, #0` (ne).

    .arch armv8.1-a
    .text

// w2 = sum of w0 over w1 passes; backward cbnz.
    .globl r_add
    .type r_add, %function
r_add:
    mov w2, wzr
1:  add w2, w2, w0
    .globl e_add_sub
e_add_sub:
    sub w1, w1, #1
    .globl s_add_cbnz
s_add_cbnz:
    cbnz w1, 1b
    .globl e_add_after
e_add_after:
    add w0, w2, w3
    ret
    .size r_add, . - r_add

// Backward b.ne on the flags of subs (or the caller's).
    .globl r_cond
    .type r_cond, %function
r_cond:
    mov w2, w0
1:  add w2, w2, #3
    .globl e_cond_subs
e_cond_subs:
    subs w1, w1, #1
    .globl s_cond_bne
s_cond_bne:
    b.ne 1b
    .globl e_cond_after
e_cond_after:
    eor w0, w2, w3
    ret
    .size r_cond, . - r_cond

// Backward tbnz: counts the shifts until the low bit is clear.
    .globl r_tbz
    .type r_tbz, %function
r_tbz:
    mov w2, w0
1:  add w2, w2, #1
    .globl e_tbz_lsr
e_tbz_lsr:
    lsr w1, w1, #1
    .globl s_tbz
s_tbz:
    tbnz w1, #0, 1b
    .globl e_tbz_after
e_tbz_after:
    add w0, w2, w1
    ret
    .size r_tbz, . - r_tbz

// A leaf, before its caller: the call to it is backward.
    .globl f_leaf
    .type f_leaf, %function
f_leaf:
    add w0, w0, #5
    ret
    .size f_leaf, . - f_leaf

    .globl r_call
    .type r_call, %function
r_call:
    mov x8, x30
    .globl s_call
s_call:
    bl f_leaf
    .globl e_call_after
e_call_after:
    add w0, w0, w2
    ret x8
    .size r_call, . - r_call

// An indirect jump to r_land.
    .globl r_br
    .type r_br, %function
r_br:
    add w0, w0, #1
    .globl s_br
s_br:
    br x9
    .size r_br, . - r_br

    .globl r_land
    .type r_land, %function
r_land:
    add w0, w0, #7
    ret
    .size r_land, . - r_land

// An atomic add on cell in a loop.
    .globl r_atomic
    .type r_atomic, %function
r_atomic:
    mov w2, w1
1:
    .globl s_atomic
s_atomic:
    ldaddal w0, w5, [x4]
    .globl e_atomic_subs
e_atomic_subs:
    subs w2, w2, #1
    .globl s_atomic_bne
s_atomic_bne:
    b.ne 1b
    .globl e_atomic_after
e_atomic_after:
    ldr w0, [x4]
    ret
    .size r_atomic, . - r_atomic

// The dispatcher: for each row (offset of the address from `rows`, w0, w1) enter it as above
// by the row's way (index & 3: 0 and 3 blr, 1 br, 2 ret), fold w0 into x19 (x19 * 1000003 +
// w0) and make a system call; x20 counts the entries.
    .globl _start
    .type _start, %function
_start:
    ldr x23, [sp]           // argc
    mov x19, xzr
    mov x20, xzr
1:  adr x21, rows
    adr x22, rows_end
2:  cmp x21, x22
    b.hs 9f
    ldr x11, [x21]
    adr x10, rows
    add x11, x11, x10
    ldr x0, [x21, #8]
    ldr x1, [x21, #16]
    and x2, x20, #3
    add w2, w2, #1
    mov x3, x20
    adr x4, cell
    adr x9, r_land
    adr x8, 6f
    and x12, x20, #3
    add x20, x20, #1
    cmp x12, #1
    b.eq 4f
    cmp x12, #2
    b.eq 5f
    cmp w1, #0
    blr x11
    b 6f
4:  mov x30, x8
    cmp w1, #0
    br x11
5:  mov x30, x8
    cmp w1, #0
    ret x11
6:  mov x12, #16963          // 1000003 = 15 << 16 + 16963
    movk x12, #15, lsl #16
    mul x19, x19, x12
    add x19, x19, w0, uxtw
    // getppid between entries: the program is one thread, so under --preempt points a point
    // is taken only at the first count after a system call (ARCHITECTURE "Compute points").
    mov x8, #173
    svc #0
    add x21, x21, #24
    b 2b
9:  cmp x23, #2
    b.lo 0f
    mov x23, xzr
    adr x0, _end
    add x0, x0, #4095
    and x0, x0, #~4095
    mov x1, #64 << 20
    mov x2, #3              // PROT_READ | PROT_WRITE
    mov x3, #0x32           // MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    mov x4, #-1
    mov x5, xzr
    mov x8, #222            // mmap
    svc #0
    b 1b
0:  // "<checksum in hex> <entries in decimal>\n" into buf
    adr x1, buf
    adr x2, hex
    mov x3, #16
7:  sub x3, x3, #1
    and x4, x19, #15
    ldrb w4, [x2, x4]
    strb w4, [x1, x3]
    lsr x19, x19, #4
    cbnz x3, 7b
    mov w4, #' '
    strb w4, [x1, #16]
    mov w4, #'\n'
    strb w4, [x1, #40]
    mov x3, #40
    mov x5, #10
8:  sub x3, x3, #1
    udiv x6, x20, x5
    msub x7, x6, x5, x20
    add w7, w7, #'0'
    strb w7, [x1, x3]
    mov x20, x6
    cbnz x20, 8b
    // buf[0..17] then buf[x3..41]
    mov x24, x3
    mov x0, #1
    mov x2, #17
    mov x8, #64             // write
    svc #0
    mov x0, #1
    adr x1, buf
    add x1, x1, x24
    mov x2, #41
    sub x2, x2, x24
    mov x8, #64
    svc #0
    mov x0, xzr
    mov x8, #93             // exit
    svc #0
    .size _start, . - _start

    .section .rodata
hex:
    .ascii "0123456789abcdef"
    .p2align 3
// Addresses as offsets from `rows`: no relocation names them (a static-PIE build has none).
#define ROW2(a, d1, s1, d2, s2) .quad a - rows, d1, s1; .quad a - rows, d2, s2
rows:
    ROW2(r_add, 3, 5, 11, 2)
    ROW2(e_add_sub, 7, 4, 2, 1)
    ROW2(s_add_cbnz, 5, 3, 9, 6)
    ROW2(e_add_after, 4, 1, 8, 2)
    ROW2(r_cond, 3, 4, 100, 2)
    ROW2(e_cond_subs, 6, 3, 13, 1)
    ROW2(s_cond_bne, 5, 2, 17, 3)
    ROW2(e_cond_after, 4, 5, 8, 2)
    ROW2(r_tbz, 3, 7, 4, 15)
    ROW2(e_tbz_lsr, 9, 3, 21, 1)
    ROW2(s_tbz, 2, 7, 30, 2)
    ROW2(e_tbz_after, 2, 5, 3, 9)
    ROW2(r_call, 3, 6, 4, 3)
    ROW2(s_call, 5, 4, 2, 2)
    ROW2(e_call_after, 7, 5, 6, 3)
    ROW2(r_br, 3, 1, 9, 2)
    ROW2(s_br, 4, 5, 6, 3)
    ROW2(r_atomic, 1, 5, 2, 9)
    ROW2(s_atomic, 3, 3, 1, 4)
    ROW2(e_atomic_subs, 2, 6, 5, 2)
    ROW2(s_atomic_bne, 4, 8, 1, 1)
    ROW2(e_atomic_after, 6, 2, 7, 1)
rows_end:

    .bss
    .p2align 3
cell:
    .quad 0
buf:
    .skip 48

    .section .note.GNU-stack, "", %progbits
