.text
.globl t
t:
c_b:      b c_b_t
c_b_t:    bl c_b
c_bself:  b .
c_blself: bl .
c_beq:    b.eq c_b
c_bgt:    b.gt c_bself
c_bnes:   b.ne .
c_bcvs:   bc.vs c_b
c_cbzw:   cbz w3, c_b
c_cbzx:   cbz x3, c_b
c_cbnzx:  cbnz x3, c_b
c_cbzzr:  cbz xzr, c_b
c_tbz33:  tbz x4, #33, c_b
c_tbnz2:  tbnz w4, #2, c_b
c_br:     br x5
c_blr:    blr x6
c_ret:    ret
c_retx7:  ret x7
c_braa:   braa x5, x9
c_braaz:  braaz x5
c_blraa:  blraa x6, sp
c_blrabz: blrabz x6
c_retaa:  retaa
c_retab:  retab
c_svc:    svc #0
c_brk:    brk #1
c_udf:    udf #0x7061
c_hlt:    hlt #0
c_eret:   eret
c_nop:    nop
c_add:    add x0, x1, x2
c_ldr:    ldr x0, [x1, #8]
c_isb:    isb
c_mrs:    mrs x0, tpidr_el0
c_casal:  casal w0, w1, [x2]
c_ldadd:  ldadd x0, x1, [x2]
c_swp:    swp w0, w1, [x2]
c_casp:   casp x0, x1, x2, x3, [x4]
c_ldar:   ldar w0, [x1]
c_stlr:   stlr w0, [x1]
c_ldapr:  ldapr w0, [x1]
c_cmpbr:  cbgt x0, x1, c_b
c_retasp: retaasppc c_b
// pairs
p_plain:  ldaxr w1, [x0]
          stlxr w2, w3, [x0]
          cbnz w2, p_plain
p_cas:    ldaxr w1, [x0]
          cmp w1, w4
          b.ne p_cas_out
          stlxr w2, w5, [x0]
          cbnz w2, p_cas
p_cas_out: ret
p_call:   ldxr x1, [x0]
          bl c_b
          stxr w2, x1, [x0]
p_far:    ldxr x1, [x0]
          .rept 32
          nop
          .endr
          stxr w2, x1, [x0]
p_edge:   ldxr x1, [x0]
          .rept 31
          nop
          .endr
          stxr w2, x1, [x0]
p_clrex:  ldaxr w1, [x0]
          cbnz w1, p_clrex_out
          clrex
p_clrex_out: nop
p_xp:     ldaxp x1, x2, [x0]
          stlxp w3, x1, x2, [x0]
p_back:   ldxr w1, [x0]
          cbnz w1, p_back
          stxr w2, w1, [x0]
p_two:    ldxr w1, [x0]
          ldxr w2, [x0]
          stxr w3, w1, [x0]
p_many:   ldxr w1, [x0]
          cbz w1, c_b
          cbz w2, c_b_t
          cbz w3, c_bself
          cbz w4, c_blself
          cbz w5, c_beq
          stxr w3, w1, [x0]
p_svc:    ldxr w1, [x0]
          svc #0
          stxr w3, w1, [x0]
p_stxr:   stxr w3, w1, [x0]
p_tbzx:   ldxrb w1, [x0]
          tbnz w1, #0, c_b
          stxrb w3, w1, [x0]
p_pre:    mov w5, #1
p_pre_l:  ldaxr w1, [x0]
          stlxr w2, w5, [x0]
          cbnz w2, p_pre
p_other:  ldaxr w1, [x0]
          stlxr w2, w5, [x0]
          cbnz w1, p_other
p_tbnz:   ldaxr w1, [x0]
          stlxr w2, w5, [x0]
          tbnz w2, #0, p_tbnz
p_xcas:   ldaxr x1, [x0]
          cmp x1, x4
          b.ne p_xcas_out
          stxr w2, x5, [x0]
          cbnz w2, p_xcas
p_xcas_out: ret
