#!/bin/sh
# Containment (ARCHITECTURE.md, "Containment"): program code that reaches into the runtime ends
# the run `unsupported`, stop `containment`, the same way on every repeat.
# - Every `syscall` byte pair in the runtime's text, jumped to from program code (`gadget N`):
#   the stub's own instruction and every other one.
# - A store at a random offset of the control region's published address, and of the boundary
#   log's, mid-run (`ctlwrite OFF BYTE`, `ctlwrite log OFF`): the message names the address.
# - The clock-moving reproducer (`ctlwrite`); a clear-tid pointer there (`tidptr`).
#@ tier=quick budget=20 slots=2 arch=x86_64
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/containment
mkdir -p "$out"
stop() { jq -r '.outcome + " " + .stop' "$1/result.json"; }
# contained NAME ARGS...: two runs end containment with one digest; prints the message.
contained() {
    n=$1; shift
    for k in a b; do
        rm -rf "$out/$n-$k"
        timeout 120 "$PATINA" run --seed 1 --out "$out/$n-$k" --mount "$G12":/guest:copy -- "$@" >/dev/null 2>&1 || true
        [ "$(stop "$out/$n-$k")" = "unsupported containment" ] || die "$n: $(stop "$out/$n-$k"): $(detail "$out/$n-$k")"
    done
    [ "$(digest "$out/$n-a")" = "$(digest "$out/$n-b")" ] || die "$n: digests differ between repeats"
}
rm -rf "$out/count"
timeout 120 "$PATINA" run --seed 1 --out "$out/count" --mount "$G12":/guest:copy -- /guest/gadget count >/dev/null 2>&1 || true
pairs=$(cat "$out/count/inc-0/stdout")
[ "${pairs:-0}" -ge 1 ] || die "gadget: no syscall byte pair found in the runtime's text"
i=0
while [ "$i" -lt "$pairs" ]; do
    contained "gadget-$i" /guest/gadget "$i"
    i=$((i + 1))
done
echo "gadget: all $pairs syscall byte pairs of the runtime's text end containment"
contained clock /guest/ctlwrite
off=$(shuf -i 0-241663 -n 1) byte=$(shuf -i 0-255 -n 1)
contained ctl /guest/ctlwrite "$off" "$byte"
addr=$(printf '%#x' $((0x602000000000 + off)))
detail "$out/ctl-a" | grep -q "$addr" || die "ctl: the message does not name $addr: $(detail "$out/ctl-a")"
echo "ctl: a store of $byte at offset $off: $(detail "$out/ctl-a")"
off=$(shuf -i 0-1048575 -n 1)
contained log /guest/ctlwrite log "$off"
addr=$(printf '%#x' $((0x603000000000 + off)))
detail "$out/log-a" | grep -q "$addr" || die "log: the message does not name $addr: $(detail "$out/log-a")"
echo "log: a store at offset $off: $(detail "$out/log-a")"
# A clear-tid pointer at the published address: ignored, as by the kernel (join then waits).
rm -rf "$out/tid"
timeout 120 "$PATINA" run --seed 1 --out "$out/tid" --mount "$G12":/guest:copy -- /guest/tidptr >/dev/null 2>&1 || true
[ "$(class "$out/tid")" = liveness ] || die "tidptr: $(class "$out/tid"): $(detail "$out/tid")"
echo "tidptr: a clear-tid pointer into the runtime's region is ignored"
rm -rf "$out"
