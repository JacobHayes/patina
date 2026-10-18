# Patina-authored EVEX length corpus. Never executed; no AVX-512 CPU required.
.text
.global patina_evex_corpus
.type patina_evex_corpus,@function
patina_evex_corpus:
    vaddps %zmm2, %zmm1, %zmm0
    vaddps %xmm2, %xmm1, %xmm0{%k1}
    vaddps %ymm2, %ymm1, %ymm0{%k1}
    vaddps %zmm2, %zmm1, %zmm0{%k1}{z}
    vaddps {rz-sae}, %zmm2, %zmm1, %zmm0
    vaddps (%rax){1to16}, %zmm1, %zmm0
    vmovdqu64 64(%rsp), %zmm0
    vmovdqu64 0x050f(%rax,%rcx,4), %zmm0
    vmovdqu64 0x050f(%rax), %zmm0
    vmovdqu64 0x050f(,%rcx,4), %zmm0
    vmovdqu64 0x050f(%rip), %zmm0
    vmovdqu64 %fs:64(%eax), %zmm0
    vpinsrw $5, %eax, %xmm1, %xmm0
    vpextrw $5, %xmm1, %eax
    vpshufd $5, %zmm1, %zmm0
    vpsrlw $5, %zmm1, %zmm0
    vpsrld $5, %zmm1, %zmm0
    vpsrlq $5, %zmm1, %zmm0
    vcmpps $5, %zmm2, %zmm1, %k1
    vshufps $5, %zmm2, %zmm1, %zmm0
    vpermb %zmm2, %zmm1, %zmm0
    vpalignr $5, 64(%rsp), %zmm1, %zmm0
    vaddph %zmm2, %zmm1, %zmm0
    vsubph -64(%rsi,%rax,2), %zmm6, %zmm0
    vmulph {rn-sae}, %zmm2, %zmm1, %zmm0
    vcvtw2ph %zmm7, %zmm7
    vmovsh 0x050f(%rip), %xmm0
    vmovw %xmm0, %eax
    vfmadd231ph %zmm1, %zmm2, %zmm0{%k1}{z}
    vfmadd231ph -64(%rcx,%rax,2), %zmm7, %zmm0
    vfmadd231ph 0x050f(%rax), %zmm1, %zmm0
    vcvtsh2ss %xmm0, %xmm0, %xmm0
    vrcpph (%rax){1to32}, %zmm3
    vcmpph $5, %zmm2, %zmm1, %k1
    ret
.size patina_evex_corpus, .-patina_evex_corpus
