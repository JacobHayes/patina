# 2 (reduced). The protocol (tests/determinism/bin/protocol.sh) over a few workloads and attack guests:
# seed 1, faults off and on, every variant but time (03-time.sh) with fewer runs (repeat 5,
# parallel 4), two cells at a time with PATINA_TEST_PARALLEL=2. The whole matrix is evidence-matrix.sh.
#@ tier=area budget=120 slots=4
. "$(dirname "$0")/lib/common.inc"
export PATINA_TEST_PARALLEL=2 DET_REPEAT=${DET_REPEAT:-5} DET_PARALLEL_RUNS=${DET_PARALLEL_RUNS:-4}
mkdir -p "$RUNS/cells"
for w in ${DET_REDUCED:-W1 W3 W8 sockprobe envprobe uninit dents}; do
    for f in off on; do echo "$w 1 $f"; done
done | xargs -P 2 -L 1 bash -euo pipefail -O inherit_errexit -c 'PROTO_OUT=$1/cells "$2/bin/protocol.sh" "$3" "$4" "$5" >"$1/cells/$3-$4-$5.txt" 2>&1 || [ $? = 1 ]; echo "$3 s$4 $5: $(grep -c " identical (" "$1/cells/$3-$4-$5.txt") identical"' \
    sh "$RUNS" "$determinism"
cat "$RUNS"/cells/*.txt >"$RUNS/summary.txt"
bad=$(awk '!/ identical \(| reference |^    / && /./ {n++} END {print n + 0}' "$RUNS/summary.txt")
echo "variants identical: $(grep -c ' identical (' "$RUNS/summary.txt"), differing or failed: $bad"
[ "$bad" = 0 ] || die "differences: $(grep -v ' identical (\| reference \|^    ' "$RUNS/summary.txt" | head -3)"
