# 3. FP/SIMD state exact across 10,000 deliveries whose handler clobbers it (x86_64: AVX and x87
# with a second thread signalling; arm64: the 32 vector registers and FPCR across a call that
# signals itself); a handler's edits to its ucontext (registers, pc past an undefined
# instruction; arm64 also a vector register, the mask and, with SVE, a P register) take effect.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
for seed in 1; do
    patina_run "$RUNS/03-fp/s$seed" "$seed" sig-fp
    check_ok "$RUNS/03-fp/s$seed" sig-fp
    cat "$RUNS/03-fp/s$seed/inc-0/stdout"
    deliveries "$RUNS/03-fp/s$seed"
done
