#!/bin/sh
# Evidence: cost of a pipe write+read pair between two threads,
# under patina and native. pipecost ping-pongs one byte over two pipes N times (2 pairs per
# round trip). Usage (from the repository root, after ./check built everything):
#   capped sh tests/io/evidence/cost.sh OUTDIR
set -eu
out=${1:?outdir}
mkdir -p "$out"
ulimit -f 8000000
root=$(cd "$(dirname "$0")/../../.." && pwd)
PATINA=${PATINA:-$root/target/release/patina}
G=${PATINA_GUESTS:?}
N=100000
cpu=$(python3 -I -c 'import os; print(sorted(os.sched_getaffinity(0))[0])')
for i in 1 2 3; do
    t0=$(date +%s%N); taskset -c "$cpu" "$G/pipecost" "$N" >/dev/null; t1=$(date +%s%N)
    echo "native pinned run $i: $(( (t1 - t0) / 1000000 )) ms"
    t0=$(date +%s%N); "$G/pipecost" "$N" >/dev/null; t1=$(date +%s%N)
    echo "native unpinned run $i: $(( (t1 - t0) / 1000000 )) ms"
    for p in 0 100; do
        d=$out/patina-p$p-$i
        taskset -c "$cpu" "$PATINA" run --seed 1 --config "$("$PATINA_CFG" preempt-permille="$p")" --out "$d" --mount "$G":/guest:copy -- /guest/pipecost "$N" >/dev/null
        python3 -I - "$d/outcome.json" "$p" "$i" <<'PY'
import json, sys
o = json.load(open(sys.argv[1]))
print(f"patina p{sys.argv[2]} run {sys.argv[3]}: {o['outcome']} {o['wall_ms']} ms, traps {o['sched']['traps']}, switches {o['sched']['switches']}, io {o['counters']['io']}")
PY
        rm -f "$d/inc-0/boundary.log"
    done
done
echo "pairs per run: $((2 * N))"
