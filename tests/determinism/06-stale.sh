#!/bin/sh
# 6. Stale-state attack: run A, then a different workload B, then A again in a new sandbox; the
# second A equals the first (digest, class, stdout): nothing leaks between runs through the host.
#@ tier=area budget=60
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/stale
mkdir -p "$out"
one() { # one NAME WORKLOAD SEED [faults]
    n=$1; w=$2; s=$3; f=${4:-off}
    wl "$w"; o="$EXTRA"; [ "$f" = on ] && o="$o $FAULTS"
    rm -rf "$out/$n"
    # shellcheck disable=SC2086
    timeout 900 "$PATINA" run --seed "$s" --out "$out/$n" --mount "$GDIR":/guest:copy $o -- $CMD >"$out/$n.txt" 2>&1 || true
    jq -r '"\(.outcome) \(.digest)"' "$out/$n/outcome.json"
}
trio() { # trio A SEED B [faults]
    a1=$(one "$1-first" "$1" "$2" "${4:-off}")
    b=$(one "$3-between" "$3" "$2" "${4:-off}")
    a2=$(one "$1-again" "$1" "$2" "${4:-off}")
    [ -n "$a1" ] || die "$1: no outcome"
    [ "$a1" = "$a2" ] || die "$1 then $3 then $1: $a1 vs $a2"
    for f in stdout stderr; do
        [ -e "$out/$1-first/inc-0/$f" ] || continue
        cmp -s "$out/$1-first/inc-0/$f" "$out/$1-again/inc-0/$f" || die "$1: $f differs after $3"
    done
    echo "$1 / $3 / $1 seed $2 faults ${4:-off}: $a1 both times (between: $b)"
    rm -rf "$out/$1-first" "$out/$1-again" "$out/$3-between"
}
trio W3 2 W9 on
trio W9 3 W3 on
trio envprobe 1 churn
trio W6 1 W5
