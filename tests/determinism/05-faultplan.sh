#!/bin/sh
# 7. Fault-plan independence: for W1 (machine crash), W3 (fs errors, path swaps), W8
# (connection resets and short chunks) and U1 (datagram drops), the boundary log with faults on equals the log with faults off up to the
# first injected fault or crash point (the fault draws do not disturb any other stream). Also:
# fault classes that never fire leave the digest unchanged.
#@ tier=quick budget=20 arch=x86_64
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/faultplan
mkdir -p "$out"
first_fault() { # 0-based index of the first inject or crash-point record of a dump
    awk '/ inject |CrashPoint/ { print NR - 1; exit }' "$1"
}
check() { # WORKLOAD SEED FAULT-OPTS...: from SEED, the first of 8 seeds at which a fault fires
    w=$1; seed=$2; shift 2
    wl "$w"
    fopts="$*"
    first=$seed last=$((seed + 7))
    while :; do
        rm -rf "$out/$w-on"
        # shellcheck disable=SC2086
        timeout 600 "$PATINA" run --seed "$seed" --out "$out/$w-on" --mount "$GDIR":/guest:copy $fopts -- $CMD >"$out/$w-on.txt" 2>&1 || true
        "$PATINA" log dump "$out/$w-on/inc-0/boundary.log" >"$out/$w-on.dump"
        ff=$(first_fault "$out/$w-on.dump")
        [ -z "$ff" ] || break
        [ "$seed" -lt "$last" ] || die "$w: no fault fired at seeds $first..$last"
        seed=$((seed + 1))
    done
    rm -rf "$out/$w-off"
    timeout 600 "$PATINA" run --seed "$seed" --out "$out/$w-off" --mount "$GDIR":/guest:copy -- $CMD >"$out/$w-off.txt" 2>&1 || true
    d=$("$PATINA" log diff "$out/$w-off/inc-0/boundary.log" "$out/$w-on/inc-0/boundary.log" | sed -n 's/^first difference at record \([0-9]*\).*/\1/p')
    [ -n "$d" ] || die "$w: logs identical although a fault fired"
    [ "$d" -ge "$ff" ] || die "$w seed $seed: logs differ at record $d, before the first fault at $ff"
    echo "$w seed $seed: first fault at record $ff, first difference at record $d"
    rm -f "$out/$w-on.dump"
}
check W1 2 --crash machine:5
check W3 3 --fault fs-error-permille=5
check W8 2 --fault net-reset-permille=30 --fault net-chunk-max=7
check W3 1 --fault path-swap-permille=300
check U1 1 --fault net-drop-permille=100

# Classes enabled but never firing: identical digest to no faults at all.
wl W1
rm -rf "$out/none" "$out/idle"
"$PATINA" run --seed 4 --out "$out/none" --mount "$GDIR":/guest:copy -- $CMD >/dev/null 2>&1
"$PATINA" run --seed 4 --out "$out/idle" --mount "$GDIR":/guest:copy --fault fs-error-permille=0 --fault fsync-error-at=999999 \
    --fault fs-short-permille=0 --fault net-reset-permille=1000 --fault net-drop-permille=1000 --fault path-swap-at=999999 --crash machine-at:999999999 -- $CMD >/dev/null 2>&1
[ "$(digest "$out/none")" = "$(digest "$out/idle")" ] || die "idle fault classes changed the digest"
echo "idle fault classes: digest unchanged $(digest "$out/none")"
