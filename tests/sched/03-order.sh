# 3. order prints at least 8 distinct logs over seeds 1-20 (one run each), and the same log for
#    the same seed (seeds 1-3 run twice).
#@ tier=area budget=60
. "$(dirname "$0")/lib.inc"
for seed in $(seq 1 20); do
    out=$RUNS/03-order/s$seed-a
    patina_run "$out" "$seed" order
    check_result "$out" order
    echo "seed $seed: $(cat "$out/inc-0/stdout")"
done
for seed in 1 2 3; do
    out=$RUNS/03-order/s$seed-b
    patina_run "$out" "$seed" order
    cmp -s "$RUNS/03-order/s$seed-a/inc-0/stdout" "$out/inc-0/stdout" || die "seed $seed: two different logs"
    lhs=$(field "$RUNS/03-order/s$seed-a/result.json" digest); rhs=$(field "$out/result.json" digest)
    [ "$lhs" = "$rhs" ] || die "seed $seed: two digests"
done
n=$(for seed in $(seq 1 20); do cat "$RUNS/03-order/s$seed-a/inc-0/stdout"; done | sort -u | wc -l)
echo "distinct logs over seeds 1-20: $n"
[ "$n" -ge 8 ] || die "only $n distinct logs"
