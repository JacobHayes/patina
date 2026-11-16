#!/bin/sh
# tests/determinism/bin/timeall.sh [WORKLOADS] [SEED]: the `time` variant for many workloads at once. Each
# workload's `patina verify --vary time` (2 runs, PATINA_TIME_GAP_S apart) is started when the
# previous one's first run has finished, so at most two sandboxes run at a time while the
# gaps overlap. Prints one line per workload. Output under $RUNS/timeall.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
. "$here/lib/workloads.inc"
: "${PATINA:?}" "${RUNS:?}"
wls=${1:-$W_ALL $A_ALL}; seed=${2:-1}
out=$RUNS/timeall
mkdir -p "$out"
for w in $wls; do
    wl "$w"
    rm -rf "${out:?}/$w"
    # shellcheck disable=SC2086
    timeout 7200 "$PATINA" verify --seed "$seed" --runs 2 --vary time --out "$out/$w" --mount "$GDIR":/guest:copy $EXTRA -- $CMD \
        >"$out/$w.txt" 2>&1 &
    until [ -e "$out/$w/run-0/result.json" ] || ! kill -0 $! 2>/dev/null; do sleep 1; done
done
wait
for w in $wls; do
    if grep -q '^identical' "$out/$w.txt"; then echo "$w s$seed time identical"
    else echo "$w s$seed time $(grep -m1 -A2 '^nondeterministic\|^first' "$out/$w.txt" | tr '\n' ' ' | cut -c1-300)"; fi
done
