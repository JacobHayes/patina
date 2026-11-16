# 2. Atomicity: 8 threads x 1,000 records of exactly 4,096 bytes into one pipe; the reader
#    never sees an interleaved record. Seed 1 at the default preemption and at 500/1000.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-atomic; mkdir -p "$o"
for p in 100 500 1000; do
    for seed in 1; do
        run_ok "$o/p$p-s$seed" "$seed" --config "$("$PATINA_CFG" preempt-permille="$p")" -- /guest/atomic
        [ "$(cat "$o/p$p-s$seed/inc-0/stdout")" = "records 8000 interleaved 0" ] || die "p$p seed $seed: $(cat "$o/p$p-s$seed/inc-0/stdout")"
        rm -f "$o/p$p-s$seed/inc-0/boundary.log"
    done
    echo "preempt $p: seed 1: 8000 records, 0 interleaved"
done
io_line atomic $(ls "$o"/*/outcome.json)
