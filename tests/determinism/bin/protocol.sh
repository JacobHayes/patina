#!/bin/bash
# tests/determinism/bin/protocol.sh WORKLOAD SEED [off|on]
# The adversarial protocol for one (workload, seed, faults) cell: a
# reference and every variant (repeat 20, cpu 6, load, aslr, sandbox, parallel, env), each an
# `patina verify` whose run 0 must also equal the reference. Prints one line per variant:
# `identical` or the first differing record. Output under $PROTO_OUT (default $RUNS/proto).
# Variant `time` needs wall-clock distance and is run by tests/determinism/03-time.sh and bin/timeall.sh.
set -euo pipefail; shopt -s inherit_errexit
here=$(cd "$(dirname "$0")/.." && pwd)
. "$here/lib/workloads.inc"
: "${PATINA:?}"
w=$1; seed=$2; f=${3:-off}
wl "$w"
opts="$EXTRA"; [ "$f" = on ] && opts="$opts $FAULTS"
out=${PROTO_OUT:-${RUNS:?}/proto}/$w/s$seed-$f
rm -rf "${out:?}"; mkdir -p "$out"
REPEAT=${DET_REPEAT:-21}
ref=""
status=0
for v in repeat cpu load aslr sandbox parallel env; do
    case $v in repeat) n=$REPEAT ;; cpu) n=6 ;; parallel) n=${DET_PARALLEL_RUNS:-9} ;; *) n=4 ;; esac
    vv=$v; [ "$v" = repeat ] && vv=repeat
    # shellcheck disable=SC2086
    if PATINA_TEST_PARALLEL=${PATINA_TEST_PARALLEL:-8} timeout 7200 "$PATINA" verify --seed "$seed" --runs "$n" --vary "$vv" --out "$out/$v" \
        --mount "$GDIR":/guest:copy $opts -- $CMD >"$out/$v.txt" 2>&1 || grep -q '^identical: ' "$out/$v.txt"; then
        d=$(jq -r .digest "$out/$v/run-0/result.json")
        c=$(jq -r .outcome "$out/$v/run-0/result.json")
        if [ -z "$ref" ]; then ref=$d; refc=$c; refdir=$out/$v/run-0; echo "$w s$seed $f reference $c $d"; fi
        if [ "$d" = "$ref" ] && [ "$c" = "$refc" ]; then
            echo "$w s$seed $f $v identical ($n runs)"
        else
            echo "$w s$seed $f $v differs from the reference: run 0 $c $d"
            # log diff exits 1: the logs differ, as the digests do.
            "$PATINA" log diff "$refdir/inc-0/boundary.log" "$out/$v/run-0/inc-0/boundary.log" >"$out/$v.diff" 2>&1 || [ $? = 1 ]
            sed -n '1,3s/^/    /p' "$out/$v.diff"
            status=1
        fi
    else
        echo "$w s$seed $f $v $(grep -m1 'divergence' "$out/$v.txt" || tail -1 "$out/$v.txt")"
        awk '/first difference/ {n = 3} n-- > 0 {print "    " $0}' "$out/$v.txt"
        status=1
    fi
    # Keep outcomes and stdout; boundary logs, operation logs and trees of identical runs are
    # not needed (the reference keeps its boundary log; trees run to 65 MB a run for W9).
    for r in "$out/$v"/run-*; do
        [ $status = 0 ] && find "$r" \( -name live.tree -o -name oplog.data -o -name post-crash \) -prune \
            -exec rm -rf {} + 2>/dev/null
        [ "$r" = "$out/repeat/run-0" ] && continue
        [ $status = 0 ] && find "$r" -name boundary.log -delete 2>/dev/null || true
    done
done
exit $status
