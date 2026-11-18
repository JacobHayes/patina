# 4. Seed sensitivity: for W1, W2, W4-W9, the digests of seeds 1-4 (faults off) include at
# least 3 distinct values (the seed reaches the schedule and the draws). 4 runs at a time.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/seeds
mkdir -p "$out"
for w in ${DET_SEED_WLS:-W1 W2 W4 W5 W6 W7 W8 W9}; do
    for s in 1 2 3 4; do echo "$w $s"; done
done | xargs -P 4 -L 1 bash -euo pipefail -O inherit_errexit -c '
    . "$1/lib/workloads.inc"
    w=$3; s=$4; o=$2/$w-$s
    wl "$w"
    rm -rf "${o:?}"
    # shellcheck disable=SC2086
    timeout 900 "$PATINA" run --seed "$s" --out "$o" --mount "$GDIR":/guest:copy $EXTRA -- $CMD >/dev/null 2>&1 || true
    jq -r .digest "$o/result.json" >"$o.digest"
    rm -rf "${o:?}"
' sh "$(cd "$(dirname "$0")" && pwd)" "$out"
fail=0
for w in ${DET_SEED_WLS:-W1 W2 W4 W5 W6 W7 W8 W9}; do
    n=$(cat "$out/$w"-*.digest | sort -u | grep -c .)
    echo "$w: $n distinct digests over 4 seeds"
    [ "$n" -ge 3 ] || fail=1
done
exit $fail
