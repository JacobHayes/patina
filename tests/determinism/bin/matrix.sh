#!/bin/sh
# tests/determinism/bin/matrix.sh [WORKLOADS] [SEEDS] [FAULTS]
# Every workload x seed x faults cell through tests/determinism/bin/protocol.sh, one cell at a time (the
# parallel variant itself runs PATINA_PARALLEL sandboxes). Defaults: W1-W9 and every attack
# guest, seeds 1-5, faults off and on. Writes $MATRIX_OUT/summary.txt (one line per variant)
# and $MATRIX_OUT/table.tsv (workload, seed, faults, variants identical, variants differing).
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
. "$here/lib/workloads.inc"
wls=${1:-$W_ALL $A_ALL}
seeds=${2:-1 2 3 4 5}
fls=${3:-off on}
out=${MATRIX_OUT:-${RUNS:?}/matrix}
mkdir -p "$out"
: >"$out/summary.txt"
printf 'workload\tseed\tfaults\tidentical\tdiffering\n' >"$out/table.tsv"
for w in $wls; do
    for s in $seeds; do
        for f in $fls; do
            PROTO_OUT=$out/cells "$here/bin/protocol.sh" "$w" "$s" "$f" >"$out/cell.txt" 2>&1
            cat "$out/cell.txt" >>"$out/summary.txt"
            ni=$(grep -c ' identical (' "$out/cell.txt")
            nd=$(grep -v ' identical (\| reference \|^    ' "$out/cell.txt" | grep -c .)
            printf '%s\t%s\t%s\t%s\t%s\n' "$w" "$s" "$f" "$ni" "$nd" >>"$out/table.tsv"
            echo "$w s$s $f: $ni identical, $nd differing"
        done
    done
done
awk -F'\t' 'NR>1{i+=$4; d+=$5} END{print "comparisons (variants): " i+d ", identical " i ", differing " d}' "$out/table.tsv"
