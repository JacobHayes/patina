#!/bin/sh
# Evidence (evidence item 5): one seed of W2, W6 and W9, faults on, DET_SOAK_RUNS times each
# (default 1000) under load and parallel (8 sandboxes at once); the first divergence fails.
#@ tier=evidence budget=1800 slots=8
set -eu
. "$(dirname "$0")/lib/common.inc"
export PATINA_PARALLEL=8
for w in ${DET_SOAK_WLS:-W2 W6 W9}; do
    sh "$determinism/bin/soak.sh" "$w" "${DET_SOAK_RUNS:-1000}" 1 || die "$w soak diverged"
done
