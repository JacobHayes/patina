# 1. sig-basic: ok and right results; identical over 4 runs (varying the CPU), seed 1; at least 3 distinct digests over seeds 1-10 (the threaded parts follow the seed).
#@ tier=quick budget=30 slots=0.5
. "$(dirname "$0")/lib.inc"
for seed in 1; do
    verify "$RUNS/01-basic/s$seed" "$seed" sig-basic 4
    echo "seed $seed: 4 identical runs, digest $(field "$RUNS/01-basic/s$seed/run-0/result.json" digest), $(grep '^schedule' "$RUNS/01-basic/s$seed/run-0/inc-0/stdout")"
done
for seed in 1 2 3 4 5 6 7 8 9 10; do
    patina_run "$RUNS/01-basic/seed-$seed" "$seed" sig-basic
    check_ok "$RUNS/01-basic/seed-$seed" sig-basic
    field "$RUNS/01-basic/seed-$seed/result.json" digest
done >"$RUNS/01-basic/digests.txt"
n=$(sort -u "$RUNS/01-basic/digests.txt" | wc -l)
echo "distinct digests over seeds 1-10: $n"
[ "$n" -ge 3 ] || die "only $n distinct digests over 10 seeds"
deliveries "$RUNS/01-basic/seed-1"
