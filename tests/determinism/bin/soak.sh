#!/bin/bash
# tests/determinism/bin/soak.sh WORKLOAD [RUNS] [SEED]: one seed of a workload with its
# faults on, RUNS times (default 1000) under `load` and `parallel` (PATINA_TEST_PARALLEL at once).
# Identical runs are removed as they are checked; the first divergence stops the soak and is
# printed with its first differing record. Output under $RUNS/soak/WORKLOAD.
set -euo pipefail; shopt -s inherit_errexit
here=$(cd "$(dirname "$0")/.." && pwd)
. "$here/lib/workloads.inc"
: "${PATINA:?}" "${RUNS:?}"
w=$1; n=${2:-1000}; seed=${3:-1}
wl "$w"
out=$RUNS/soak/$w
rm -rf "${out:?}"; mkdir -p "$(dirname "$out")"
# shellcheck disable=SC2086
PATINA_TEST_VERIFY_PRUNE=1 timeout 36000 "$PATINA" verify --seed "$seed" --runs "$n" --vary load,parallel --out "$out" \
    --mount "$GDIR":/guest:copy $EXTRA $FAULTS -- $CMD >"$out.txt" 2>&1 && st=0 || st=$?
grep -q '^identical: ' "$out.txt" && st=0
echo "$w seed $seed faults on: $(tail -1 "$out.txt") (status $st)"
grep -A3 '^divergence' "$out.txt" || true
exit $st
