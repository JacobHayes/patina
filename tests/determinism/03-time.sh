#!/bin/sh
# 1 (time). Nothing in any output correlates with wall time: timeprobe prints every clock, timer
# and timestamp it reaches, at start and after a 60-virtual-second sleep, in two runs started
# DET_TIME_GAP_S apart (default 5 s: any host clock that leaks differs by that much). The
# 600 s gap of the full matrix, over every workload, is tests/determinism/evidence-time.sh.
#@ tier=area budget=60
set -eu
. "$(dirname "$0")/lib/common.inc"
gap=${DET_TIME_GAP_S:-5}
rm -rf "$RUNS/time"
PATINA_TIME_GAP_S=$gap timeout 1800 "$PATINA" verify --seed 3 --runs 2 --vary time --out "$RUNS/time" \
    --mount "$PATINA_ATTACK_GUESTS":/guest:copy -- /guest/timeprobe >"$RUNS/time.txt" 2>&1 || grep -q '^identical: ' "$RUNS/time.txt" || die "$(tail -3 "$RUNS/time.txt")"
echo "timeprobe: 2 runs $gap s apart identical ($(digest "$RUNS/time/run-0"))"
