# 3. FP and AVX state exact across 10,000 deliveries whose handler clobbers it; a handler's
# edits to its ucontext (rax, rip past a ud2) take effect.
#@ tier=quick budget=30 arch=x86_64
. "$(dirname "$0")/lib.inc"
for seed in 1; do
    patina_run "$RUNS/03-fp/s$seed" "$seed" sig-fp
    check_ok "$RUNS/03-fp/s$seed" sig-fp
    cat "$RUNS/03-fp/s$seed/inc-0/stdout"
    deliveries "$RUNS/03-fp/s$seed"
done
