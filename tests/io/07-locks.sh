# 7. Locks: two threads contend for flock and F_OFD_SETLKW on one file; mutual exclusion
#    holds (the guest counts violations), identical across runs.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/07-locks; mkdir -p "$o"
for seed in 1; do
    verify_ok "$o/v$seed" "$seed" 4 -- /guest/locks
    [ "$(cat "$o/v$seed/run-0/inc-0/stdout")" = "flock entries 400 violations 0
ofd entries 400 violations 0" ] || die "seed $seed: $(cat "$o/v$seed/run-0/inc-0/stdout")"
done
for p in 500 1000; do
    run_ok "$o/p$p" 1 --preempt-permille "$p" -- /guest/locks
    echo "preempt $p: $(tr '\n' ' ' <"$o/p$p/inc-0/stdout")"
done
io_line locks $(ls "$o"/v*/run-0/outcome.json "$o"/p*/outcome.json)
