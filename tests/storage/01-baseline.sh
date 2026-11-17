# 1. W9 clean baseline (reduced: 40 seeds per build; the 200-seed sweeps are in docs/EVIDENCE.md).
# No faults, no crash: every seed ok, debug and release. With --crash process:3 the only
# failures allowed are F1 (open-after-crash).
#@ tier=area budget=90 slots=4
. "$(dirname "$0")/lib/common.inc"
for b in debug release; do
    sweep clean-$b fjall-harness 1-40 -- -- /guest/fjall-harness-$b >/dev/null
    [ "$(count clean-$b ok)" = 40 ] || die "clean $b: not all ok ($(tail -1 "$RUNS/clean-$b.table"))"
done
sweep process3 fjall-harness 1-40 -- --crash process:3 -- /guest/fjall-harness-debug >/dev/null
other=$(awk -F'\t' 'NR>1 && $2!="ok" && $3!~/^open-after-crash: /' "$RUNS/process3/summary.tsv" | wc -l)
[ "$other" = 0 ] || die "process:3: $other failures other than F1"
tables
