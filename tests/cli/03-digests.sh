# 3. Two runs of one seed have equal digests; two seeds give different digests.
#@ tier=quick budget=5
. "$(dirname "$0")/lib.inc"
for r in 1a:1 1b:1 2:2; do
    prun "$RUNS/s${r%%:*}" --seed "${r#*:}" -- "$PATINA_GUESTS/hello-static"
    [ "$st" = 0 ] || die "seed ${r#*:}: exit $st ($(tail -2 "$RUNS/s${r%%:*}.txt"))"
done
a=$(field "$RUNS/s1a/result.json" digest) b=$(field "$RUNS/s1b/result.json" digest) c=$(field "$RUNS/s2/result.json" digest)
[ "$a" = "$b" ] || die "seed 1 twice: $a vs $b"
[ "$a" != "$c" ] || die "seeds 1 and 2: the same digest $a"
echo "seed 1 twice: $a; seed 2: $c"
