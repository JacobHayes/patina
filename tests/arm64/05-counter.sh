# 5. The counter-timer trap: reads of CNTFRQ_EL0 and CNTVCT_EL0 answer from virtual time, so
# two runs print the same values (the real counter moves between runs) and the counter goes
# forward between reads.
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
for k in a b; do
    prun "$RUNS/$k" --seed 1 -- "$PATINA_GUESTS/counter"
    [ "$st" = 0 ] || die "$k: exit $st ($(tail -2 "$RUNS/$k.txt"))"
done
cmp -s "$RUNS/a/inc-0/stdout" "$RUNS/b/inc-0/stdout" || die "the reads differ between runs: $(tr '\n' ' ' <"$RUNS/a/inc-0/stdout") vs $(tr '\n' ' ' <"$RUNS/b/inc-0/stdout")"
awk '/^cntvct/ { if (NR > 2 && $2 <= last) bad = 1; last = $2 } END { exit bad }' "$RUNS/a/inc-0/stdout" ||
    die "the counter did not go forward: $(tr '\n' ' ' <"$RUNS/a/inc-0/stdout")"
cat "$RUNS/a/inc-0/stdout"
