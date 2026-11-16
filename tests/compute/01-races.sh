#!/bin/sh
# Syscall-free races found by compute points (tests/guests/compute): with compute-gap=8, over
# seeds 1-40, `races b` (check-then-act with no system call in the window) and `pool` (a lost
# update in `stats.done++`, one instruction in the stock -O2 build) each end `failure` on at
# least one seed; the first failing seed of each replays identical, and `races b`'s three runs
# under --vary cpu,aslr give one digest.
#@ tier=quick budget=20 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-races
mkdir -p "$o"
for p in "races b" pool; do
    n=${p%% *}
    seq 1 40 | xargs -P 6 -I{} sh -c '
        d=$1/$2-$3; rm -rf "$d"
        timeout 60 "$PATINA" run --seed "$3" --fault compute-gap=8 --out "$d" --mount "$4":/guest:copy -- /guest/compute/$5 >/dev/null 2>&1 || true' \
        sh "$o" "$n" {} "$G" "$p"
    first=""
    found=0
    for s in $(seq 1 40); do
        [ -f "$o/$n-$s/result.json" ] || die "$n seed $s: no result.json"
        case $(field "$o/$n-$s/result.json" outcome) in
            failure) found=$((found + 1)); [ -n "$first" ] || first=$s ;;
            ok) ;;
            *) die "$n seed $s: $(res "$o/$n-$s")" ;;
        esac
    done
    [ -n "$first" ] || die "$n: no failure in seeds 1-40 at compute-gap=8 (switches on seed 1: $(field "$o/$n-1/result.json" compute.switches))"
    "$PATINA" replay "$o/$n-$first" >"$o/$n-replay.txt" 2>&1 || true
    grep -q '^identical' "$o/$n-replay.txt" || die "$n seed $first does not replay: $(head -3 "$o/$n-replay.txt")"
    echo "$p: failure on $found of 40 seeds (first $first: $(tail -1 "$o/$n-$first/inc-0/stdout")); it replays identical"
    [ "$n" = races ] && rb=$first
done
rm -rf "$o/verify"
"$PATINA" verify --runs 3 --vary cpu,aslr --seed "$rb" --fault compute-gap=8 --out "$o/verify" \
    --mount "$G":/guest:copy -- /guest/compute/races b >"$o/verify.txt" 2>&1 || true
grep -q '^identical: 3 runs' "$o/verify.txt" || die "races b seed $rb under --vary cpu,aslr: $(tail -3 "$o/verify.txt")"
echo "races b seed $rb: identical over 3 runs varying cpu and aslr"
