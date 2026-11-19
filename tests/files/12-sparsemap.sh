# 12. A sparse file mapped large (fs sparsemap: 2 GiB MAP_SHARED of a file grown to 1 GiB,
#     two pages written through the mapping, shrunk and grown again): ok with the guest's own
#     checks, the operation log replays to the live tree (--crash with a crash point past the
#     run's end), and Patina's memory follows what was written, not what was mapped: the
#     largest resident set of the run's processes stays under 256 MiB (the kernel's
#     high-water mark, not a sample). Patina's copy of a mapping goes with the part unmapped:
#     a 16 MiB mapping cut into pieces 32 times keeps the largest resident set under 160 MiB
#     (it reached 298 MiB when the cut parts stayed); and its address space is reused: 48
#     mappings of 1 GiB, one after another, end ok (past half the runtime's 64 GiB region).
#@ tier=quick budget=20
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/12-sparsemap
mb=$(python3 -I "$(dirname "$0")/../maxrss-mb.py" timeout 120 "$PATINA" run --seed 1 --crash machine-at:1000000 \
    --out "$o" --mount "$PATINA_GUESTS":/guest:copy -- /guest/sparsemap)
[ "$(field "$o/result.json" outcome)" = ok ] && grep -qx 'sparsemap ok' "$o/inc-0/stdout" ||
    die "sparsemap: $(field "$o/result.json" outcome) $(field "$o/result.json" message) $(cat "$o/inc-0/stdout" 2>/dev/null)"
[ "$mb" -lt 256 ] || die "sparsemap: largest resident set $mb MiB"
echo "sparsemap: ok, largest resident set $mb MiB, $(grep allocated "$o/inc-0/stdout")"
for m in cuts many; do
    mb=$(python3 -I "$(dirname "$0")/../maxrss-mb.py" timeout 120 "$PATINA" run --seed 1 --out "$o-$m" \
        --mount "$PATINA_GUESTS":/guest:copy -- /guest/sparsemap "$m")
    [ "$(field "$o-$m/result.json" outcome)" = ok ] && grep -qx "$m ok" "$o-$m/inc-0/stdout" ||
        die "sparsemap $m: $(field "$o-$m/result.json" outcome) $(field "$o-$m/result.json" message)"
    [ "$m" != cuts ] || [ "$mb" -lt 160 ] || die "sparsemap cuts: largest resident set $mb MiB"
    echo "sparsemap $m: ok, largest resident set $mb MiB"
    rm -rf "${o:?}-$m"
done
