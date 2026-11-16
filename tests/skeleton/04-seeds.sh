# 4. Seeds 1 and 2 give different stdout (random bytes differ) and different digests.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
for g in $GUESTS; do
    for s in 1 2; do patina_run "$RUNS/04-seeds/$g-s$s" "$s" "$g"; done
    a=$RUNS/04-seeds/$g-s1; b=$RUNS/04-seeds/$g-s2
    [ "$(field "$a/outcome.json" outcome)" = ok ] && [ "$(field "$b/outcome.json" outcome)" = ok ] || die "$g: not ok"
    cmp -s "$a/inc-0/stdout" "$b/inc-0/stdout" && die "$g: same stdout for seeds 1 and 2"
    ra=$(grep '^random ' "$a/inc-0/stdout"); rb=$(grep '^random ' "$b/inc-0/stdout")
    [ "$ra" != "$rb" ] || die "$g: same random bytes"
    [ "$(field "$a/outcome.json" digest)" != "$(field "$b/outcome.json" digest)" ] || die "$g: same digest"
    echo "$g: seeds differ ($ra / $rb)"
done
