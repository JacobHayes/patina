# 12. A sparse file mapped large (fs sparsemap: 2 GiB MAP_SHARED of a file grown to 1 GiB,
#     two pages written through the mapping, shrunk and grown again): ok with the guest's own
#     checks, the operation log replays to the live tree (--fault crash-at with a crash point past the
#     run's end), and Patina's memory follows what was written, not what was mapped: the
#     largest resident set of the run's processes stays under 256 MiB (the kernel's
#     high-water mark, not a sample), and the shadow store (Patina's copy of what the log holds
#     of a mapped file, `shadow_bytes`) stays under 16 MiB (huge pages allowed). A 16 MiB
#     mapping cut into pieces 32 times keeps the largest resident set under 160 MiB; a
#     1 GiB file mapped 48 times, one after another, ends ok with the store under 16 MiB.
#     munmaps the kernel refuses (length 0) change nothing Patina tracks: 200 of them inside one
#     mapping, then its tail written and another file mapped, end ok and
#     the operation log replays to the live tree.
#@ tier=quick budget=20 slots=0.5
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/12-sparsemap
mb=$(python3 -I "$(dirname "$0")/../maxrss-mb.py" timeout 120 "$PATINA" run --seed 1 --fault crash-at=1000000 \
    --out "$o" --mount "$PATINA_GUESTS":/guest:copy -- /guest/sparsemap)
[ "$(field "$o/result.json" outcome)" = ok ] && grep -qx 'sparsemap ok' "$o/inc-0/stdout" ||
    die "sparsemap: $(field "$o/result.json" outcome) $(field "$o/result.json" message) $(cat "$o/inc-0/stdout" 2>/dev/null)"
[ "$mb" -lt 256 ] || die "sparsemap: largest resident set $mb MiB"
sb=$(field "$o/result.json" shadow_bytes)
[ "$sb" -lt $((16 << 20)) ] || die "sparsemap: the shadow store held $sb bytes"
echo "sparsemap: ok, largest resident set $mb MiB, shadow store $sb bytes, $(grep allocated "$o/inc-0/stdout")"
for m in cuts many refused; do
    crash=()
    [ "$m" != refused ] || crash=(--fault crash-at=1000000)
    mb=$(python3 -I "$(dirname "$0")/../maxrss-mb.py" timeout 120 "$PATINA" run --seed 1 "${crash[@]}" --out "$o-$m" \
        --mount "$PATINA_GUESTS":/guest:copy -- /guest/sparsemap "$m")
    [ "$(field "$o-$m/result.json" outcome)" = ok ] && grep -qx "$m ok" "$o-$m/inc-0/stdout" ||
        die "sparsemap $m: $(field "$o-$m/result.json" outcome) $(field "$o-$m/result.json" message)"
    [ "$m" != cuts ] || [ "$mb" -lt 160 ] || die "sparsemap cuts: largest resident set $mb MiB"
    sb=$(field "$o-$m/result.json" shadow_bytes)
    [ "$m" != many ] || [ "$sb" -lt $((16 << 20)) ] || die "sparsemap many: the shadow store held $sb bytes"
    echo "sparsemap $m: ok, largest resident set $mb MiB, shadow store $sb bytes"
    rm -rf "${o:?}-$m"
done
