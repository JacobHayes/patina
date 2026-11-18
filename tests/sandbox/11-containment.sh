# Containment (ARCHITECTURE.md, "Containment"): program code that reaches into the runtime ends
# the run `unsupported`, stop `containment`, the same way on every repeat.
# - Every `syscall` byte pair in the runtime's text, jumped to from program code (`gadget N`):
#   the stub's own instruction and every other one.
# - A store at a random offset of the control region's published address, and of the boundary
#   log's, mid-run (`ctlwrite OFF BYTE`, `ctlwrite log OFF`): the message names the address.
# - The clock-moving reproducer (`ctlwrite`); a clear-tid pointer there (`tidptr`).
# - System calls given pointers into the runtime's region (`ptrprobe`: both directions, inside
#   iovecs and msghdrs, and the memory calls on ranges there) answer what the kernel answers for
#   a hole, as a native run of the same program shows, and move none of the runtime's bytes.
#@ tier=quick budget=20 slots=2
. "$(dirname "$0")/lib/common.inc"
: "${RT_BIN:?}"
out=$RUNS/containment
mkdir -p "$out"
# The runtime's loadable segments (vaddr memsz), text first.
segs=$(python3 -I -c '
import struct, sys
b = open(sys.argv[1], "rb").read()
phoff, = struct.unpack_from("<Q", b, 32)
phentsize, phnum = struct.unpack_from("<HH", b, 54)
for i in range(phnum):
    t, _, _, vaddr, _, _, memsz, _ = struct.unpack_from("<IIQQQQQQ", b, phoff + i * phentsize)
    if t == 1:
        print(vaddr, memsz)' "$RT_BIN")
text=$(echo "$segs" | awk 'NR == 1 {print $2}')
data=$(echo "$segs" | awk 'NR == 2 {print $1}')
[ "${text:-0}" -gt 0 ] && [ "${data:-0}" -gt 0 ] || die "no text and data segments in $RT_BIN"
stop() { jq -r '.outcome + " " + .stop' "$1/result.json"; }
# contained NAME ARGS...: two runs end containment with one digest; prints the message.
contained() {
    n=$1; shift
    for k in a b; do
        rm -rf "${out:?}/$n-$k"
        timeout 120 "$PATINA" run --seed 1 --out "$out/$n-$k" --mount "$G12":/guest:copy -- "$@" >/dev/null 2>&1 || true
        [ "$(stop "$out/$n-$k")" = "unsupported containment" ] || die "$n: $(stop "$out/$n-$k"): $(detail "$out/$n-$k")"
    done
    lhs=$(digest "$out/$n-a"); rhs=$(digest "$out/$n-b")
    [ "$lhs" = "$rhs" ] || die "$n: digests differ between repeats"
}
rm -rf "${out:?}/count"
timeout 120 "$PATINA" run --seed 1 --out "$out/count" --mount "$G12":/guest:copy -- /guest/gadget count "$text" >/dev/null 2>&1 || true
pairs=$(head -1 "$out/count/inc-0/stdout")
[ "${pairs:-0}" -ge 1 ] || die "gadget: no syscall byte pair found in the runtime's text"
i=0
while [ "$i" -lt "$pairs" ]; do
    contained "gadget-$i" /guest/gadget "$i" "$text"
    i=$((i + 1))
done
echo "gadget: all $pairs syscall byte pairs of the runtime's text end containment"
# Pointers into the runtime's region: its text, data (`state::PROC`), private memory
# (alternate stacks), the published and drawn windows of the control region and the log, its
# last page.
addrs=$(printf '%#x ' 0x600000000000 "$data" 0x601000000000 0x601000040000 0x601000080000 \
    0x602000000000 0x602100000000 0x603000000000 0x603100000000 0x603ffffff000)
for k in a b; do
    rm -rf "${out:?}/ptr-$k"
    timeout 120 "$PATINA" run --seed 1 --out "$out/ptr-$k" --mount "$G12":/guest:copy -- /guest/ptrprobe $addrs >/dev/null 2>&1 || true
    [ "$(class "$out/ptr-$k")" = ok ] || die "ptrprobe: $(class "$out/ptr-$k"): $(detail "$out/ptr-$k"); $(grep -m3 DIFF "$out/ptr-$k/inc-0/stdout")"
done
lhs=$(digest "$out/ptr-a"); rhs=$(digest "$out/ptr-b")
[ "$lhs" = "$rhs" ] || die "ptrprobe: digests differ between repeats"
"$G12/ptrprobe" $addrs >"$out/ptr-native.txt" 2>&1 || die "ptrprobe natively: $(grep -m3 DIFF "$out/ptr-native.txt")"
grep -v '^story ' "$out/ptr-native.txt" >"$out/ptr-native.cmp"
grep -v '^story ' "$out/ptr-a/inc-0/stdout" >"$out/ptr-patina.cmp"
cmp -s "$out/ptr-native.cmp" "$out/ptr-patina.cmp" ||
    die "ptrprobe: differs from the native run: $(diff "$out/ptr-native.cmp" "$out/ptr-patina.cmp" | head -5)"
# FNV-1a of nothing: no byte arrived.
grep -qx 'learned cbf29ce484222325' "$out/ptr-patina.cmp" || die "ptrprobe: bytes arrived: $(grep '^learned ' "$out/ptr-patina.cmp")"
grep '^story munmap ' "$out/ptr-a/inc-0/stdout" | awk '$4 != -22 {bad = 1} END {exit bad || NR == 0}' ||
    die "ptrprobe: munmap in the region: $(grep -m3 '^story munmap ' "$out/ptr-a/inc-0/stdout")"
grep -qx 'story task-mem -2' "$out/ptr-a/inc-0/stdout" ||
    die "ptrprobe: /proc/self/task/TID/mem through the task directory: $(grep task-mem "$out/ptr-a/inc-0/stdout")"
grep -qx 'story straddle-write -14 drained 0' "$out/ptr-a/inc-0/stdout" ||
    die "ptrprobe: a buffer into the region: $(grep straddle "$out/ptr-a/inc-0/stdout")"
echo "ptrprobe: $(grep -vc '^story \|^learned ' "$out/ptr-patina.cmp") calls with pointers into the runtime's region answer as natively for a hole; no byte of the runtime's arrived"
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
rm -rf "${out:?}/tid"
# lint-allow: seed — the join waits for ever on every seed (natively too)
timeout 120 "$PATINA" run --seed 1 --out "$out/tid" --mount "$G12":/guest:copy -- /guest/tidptr >/dev/null 2>&1 || true
[ "$(class "$out/tid")" = liveness ] || die "tidptr: $(class "$out/tid"): $(detail "$out/tid")"
echo "tidptr: a clear-tid pointer into the runtime's region is ignored"
rm -rf "${out:?}"
