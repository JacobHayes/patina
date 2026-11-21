# 2. Atomicity: 8 threads x 1,000 records of exactly 4,096 bytes into one pipe; the reader
#    never sees an interleaved record. Seed 1 at preempt-permille 1000 (the area tier 100 and
#    500 too).
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-atomic; mkdir -p "$o"
ps="100 500 1000"; [ "${CHECK_TIER:-}" != quick ] || ps=1000
for p in $ps; do
    for seed in 1; do
        run_ok "$o/p$p-s$seed" "$seed" --config "$("$PATINA_CFG" preempt-permille="$p")" -- /guest/atomic
        [ "$(cat "$o/p$p-s$seed/inc-0/stdout")" = "records 8000 interleaved 0" ] || die "p$p seed $seed: $(cat "$o/p$p-s$seed/inc-0/stdout")"
        rm -f "$o/p$p-s$seed/inc-0/boundary.log"
    done
    echo "preempt $p: seed 1: 8000 records, 0 interleaved"
done
io_line atomic $(ls "$o"/*/result.json)
