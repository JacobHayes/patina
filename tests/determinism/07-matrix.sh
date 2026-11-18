# 7. The release tier's determinism matrix: W1 (threads, files, machine crashes), W2 (tokio),
# W4 (Go), W6 (a shell pipeline), W8 (sockets) and two attack guests (directory listing order,
# epoll order) x seeds 1-2 x faults off and on (the workload table's fault options), each
# `patina verify --runs 3 --vary cpu,aslr`: every cell identical. The evidence tier's matrix
# has every workload and every variant.
#@ tier=release budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
mkdir -p "$RUNS/cells"
# Guest-minor order, so the four cells at once are four guests: epollorder's 500 pipes, run four
# at a time, pass the per-user pipe-buffer limit (pipe-user-pages-soft) and end `infra`.
for s in 1 2; do
    for f in off on; do
        for w in W1 W2 W4 W6 W8 dents epollorder; do echo "$w $s $f"; done
    done
done | xargs -P 4 -L 1 bash -euo pipefail -O inherit_errexit -c '
    . "$1/lib/workloads.inc"
    w=$3 s=$4 f=$5 o=$2/cells/$3-$4-$5
    wl "$w"
    [ "$f" = off ] || EXTRA="$EXTRA $FAULTS"
    # shellcheck disable=SC2086
    PATINA_PARALLEL=1 timeout 600 "$PATINA" verify --seed "$s" --runs 3 --vary cpu,aslr --out "$o" \
        --mount "$GDIR":/guest:copy $EXTRA -- $CMD >"$o.txt" 2>&1 || true
    echo "$w seed $s faults $f: $(grep -m1 "^identical\|differ\|error" "$o.txt" || tail -1 "$o.txt")"
    rm -rf "${o:?}"
' sh "$determinism" "$RUNS" | sort | tee "$RUNS/summary.txt"
n=$(awk '/: identical: 3 runs/ {n++} END {print n + 0}' "$RUNS/summary.txt")
echo "cells identical: $n of 28"
[ "$n" = 28 ] || die "$(grep -v ': identical: 3 runs' "$RUNS/summary.txt" | head -5)"
