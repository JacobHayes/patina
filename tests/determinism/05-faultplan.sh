#!/bin/sh
# 7. Fault-plan independence: for W1 (machine crash), W3 (fs errors) and W8 (connection resets
# and short chunks), the boundary log with faults on equals the log with faults off up to the
# first injected fault or crash point (the fault draws do not disturb any other stream). Also:
# fault classes that never fire leave the digest unchanged.
#@ tier=quick budget=20
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/faultplan
mkdir -p "$out"
first_fault() { # 0-based index of the first inject or crash-point record of a dump
    awk '/ inject |CrashPoint/ { print NR - 1; exit }' "$1"
}
check() {
    w=$1; seed=$2; shift 2
    wl "$w"
    fopts="$*"
    for f in off on; do
        rm -rf "$out/$w-$f"
        o=""; [ $f = on ] && o=$fopts
        # shellcheck disable=SC2086
        timeout 600 "$PATINA" run --seed "$seed" --out "$out/$w-$f" --guest "$GDIR" $o -- $CMD >"$out/$w-$f.txt" 2>&1 || true
    done
    "$PATINA" log dump "$out/$w-on/inc-0/boundary.log" >"$out/$w-on.dump"
    ff=$(first_fault "$out/$w-on.dump")
    [ -n "$ff" ] || die "$w seed $seed: no fault fired (choose another seed)"
    d=$("$PATINA" log diff "$out/$w-off/inc-0/boundary.log" "$out/$w-on/inc-0/boundary.log" | sed -n 's/^first difference at record \([0-9]*\).*/\1/p')
    [ -n "$d" ] || die "$w: logs identical although a fault fired"
    [ "$d" -ge "$ff" ] || die "$w seed $seed: logs differ at record $d, before the first fault at $ff"
    echo "$w seed $seed: first fault at record $ff, first difference at record $d"
    rm -f "$out/$w-on.dump"
}
check W1 2 --crash machine:5
check W3 3 --fault fs-error-permille=5
check W8 2 --fault net-reset-permille=30 --fault net-chunk-max=7

# Classes enabled but never firing: identical digest to no faults at all.
wl W1
rm -rf "$out/none" "$out/idle"
"$PATINA" run --seed 4 --out "$out/none" --guest "$GDIR" -- $CMD >/dev/null 2>&1
"$PATINA" run --seed 4 --out "$out/idle" --guest "$GDIR" --fault fs-error-permille=0 --fault fsync-error-at=999999 \
    --fault short-permille=0 --fault net-reset-permille=1000 --crash machine-at:999999999 -- $CMD >/dev/null 2>&1
[ "$(digest "$out/none")" = "$(digest "$out/idle")" ] || die "idle fault classes changed the digest"
echo "idle fault classes: digest unchanged $(digest "$out/none")"
