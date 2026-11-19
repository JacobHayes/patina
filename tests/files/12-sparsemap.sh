# 12. A sparse file mapped large (fs sparsemap: 2 GiB MAP_SHARED of a file grown to 1 GiB,
#     two pages written through the mapping, shrunk and grown again): ok with the guest's own
#     checks, the operation log replays to the live tree (--crash with a crash point past the
#     run's end), and Patina's memory follows what was written, not what was mapped: the
#     largest resident set of the run's processes stays under 256 MiB (the kernel's
#     high-water mark, not a sample).
#@ tier=quick budget=20
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/12-sparsemap
mb=$(python3 -I "$(dirname "$0")/../maxrss-mb.py" timeout 120 "$PATINA" run --seed 1 --crash machine-at:1000000 \
    --out "$o" --mount "$PATINA_GUESTS":/guest:copy -- /guest/sparsemap)
[ "$(field "$o/result.json" outcome)" = ok ] && grep -qx 'sparsemap ok' "$o/inc-0/stdout" ||
    die "sparsemap: $(field "$o/result.json" outcome) $(field "$o/result.json" message) $(cat "$o/inc-0/stdout" 2>/dev/null)"
[ "$mb" -lt 256 ] || die "sparsemap: largest resident set $mb MiB"
echo "sparsemap: ok, largest resident set $mb MiB, $(grep allocated "$o/inc-0/stdout")"
