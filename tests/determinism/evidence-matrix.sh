# Evidence (docs/EVIDENCE.md): the whole protocol (tests/determinism/bin/protocol.sh:
# reference, repeat 21, cpu 6, load, aslr, sandbox, parallel 9, env) over every W1-W9 workload
# and attack guest, seeds DET_SEEDS (default "1 2"), faults off
# and on. Cells run 4 at a time, each with PATINA_TEST_PARALLEL=2.
#@ tier=evidence budget=2400 slots=8 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
export PATINA_TEST_PARALLEL=2 DET_PARALLEL_RUNS=${DET_PARALLEL_RUNS:-4}
mkdir -p "$RUNS/cells"
for w in ${DET_WLS:-$W_ALL $A_ALL}; do
    for s in ${DET_SEEDS:-1 2}; do
        for f in off on; do echo "$w $s $f"; done
    done
done | xargs -P 4 -L 1 bash -euo pipefail -O inherit_errexit -c 'PROTO_OUT=$1/cells "$2/bin/protocol.sh" "$3" "$4" "$5" >"$1/cells/$3-$4-$5.txt" 2>&1 || [ $? = 1 ]; echo "$3 s$4 $5: $(grep -c " identical (" "$1/cells/$3-$4-$5.txt") identical"' \
    sh "$RUNS" "$determinism"
cat "$RUNS"/cells/*.txt >"$RUNS/summary.txt"
bad=$(awk '!/ identical \(| reference |^    / && /./ {n++} END {print n + 0}' "$RUNS/summary.txt")
echo "variants identical: $(grep -c ' identical (' "$RUNS/summary.txt"), differing or failed: $bad"
[ "$bad" = 0 ] || die "$(grep -v ' identical (\| reference \|^    ' "$RUNS/summary.txt" | head -5)"
