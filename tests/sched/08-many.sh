# 8. 5,000 threads created and joined in batches of 50: ok, no slot or memory exhaustion,
#    the printed tids are identical across two runs.
#@ tier=area budget=60 arch=x86_64
. "$(dirname "$0")/lib.inc"
for rep in a b; do
    out=$RUNS/08-many/$rep
    patina_run "$out" 1 many
    [ "$(field "$out/result.json" outcome)" = ok ] || die "$rep: class $(field "$out/result.json" outcome) $(field "$out/result.json" message)"
    n=$(wc -l <"$out/inc-0/stdout")
    u=$(sort -u "$out/inc-0/stdout" | wc -l)
    [ "$n" = 5000 ] && [ "$u" = 5000 ] || die "$rep: $n tids, $u distinct"
done
cmp -s "$RUNS/08-many/a/inc-0/stdout" "$RUNS/08-many/b/inc-0/stdout" || die "tids differ between runs a and b"
echo "5000 threads, tids $(head -1 "$RUNS/08-many/a/inc-0/stdout")..$(tail -1 "$RUNS/08-many/a/inc-0/stdout") identical in 2 runs, wall_ms $(field "$RUNS/08-many/a/result.json" wall_ms)"
