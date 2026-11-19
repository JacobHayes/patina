# 13. A sandbox tmpfs filled (statfs fill: /tmp written until a write fails) with
#     --tmpfs-bytes 8 MiB: /tmp reports that size, the write past it answers ENOSPC after at
#     most that many bytes, result.json counts the ENOSPC with the size, and `patina run`
#     names the flag that sets it; a `:copy` mount larger than the size (the guest set)
#     ends the run naming it too.
#@ tier=quick budget=10
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/13-tmpfs-full
size=$((8 << 20))
said=$("$PATINA" run --seed 1 --tmpfs-bytes $size --out "$o" --mount "$PATINA_GUESTS":/guest -- /guest/statfs fill 2>&1) ||
    die "statfs fill: $said"
out=$o/inc-0/stdout
read -r n e < <(sed -n 's/^filled \([0-9]*\) errno=\([0-9]*\)$/\1 \2/p' "$out")
[ "$e" = 28 ] && [ "$n" -gt $((size / 2)) ] && [ "$n" -le "$size" ] || die "filled: $(cat "$out")"
grep -q "^statfs /tmp .* blocks=$((size / 4096)) " "$out" || die "/tmp: $(grep '^statfs /tmp' "$out")"
r=$(python3 -I -c 'import json, sys; t = json.load(open(sys.argv[1]))["tmpfs"]; print(t["bytes"], t["enospc"])' "$o/result.json")
[ "${r% *}" = "$size" ] && [ "${r#* }" -ge 1 ] || die "result.json tmpfs: $r"
grep -q -- '--tmpfs-bytes' <<<"$said" || die "the run does not name --tmpfs-bytes: $said"
st=0
"$PATINA" run --seed 1 --tmpfs-bytes $size --out "$o-copy" --mount "$PATINA_GUESTS":/guest:copy -- /guest/statfs >/dev/null 2>&1 || st=$?
[ $st != 0 ] && grep -q -- '--tmpfs-bytes' <<<"$(field "$o-copy/result.json" message)" ||
    die "a copy too large for the tmpfs: $st $(field "$o-copy/result.json" message)"
echo "tmpfs full: $n bytes written into an 8 MiB /tmp, then ENOSPC; ${r#* } calls counted and the flag named"
