# 4. Seeds 1 and 2 give different stdout (random bytes differ) and different digests, for every guest.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
for g in $GUESTS; do
    for s in 1 2; do patina_run "$RUNS/04-seeds/$g-s$s" "$s" "$g"; done
    a=$RUNS/04-seeds/$g-s1; b=$RUNS/04-seeds/$g-s2
    [ "$(field "$a/result.json" outcome)" = ok ] && [ "$(field "$b/result.json" outcome)" = ok ] || die "$g: not ok"
    cmp -s "$a/boot-1/stdout" "$b/boot-1/stdout" && die "$g: same stdout for seeds 1 and 2"
    ra=$(grep '^random ' "$a/boot-1/stdout"); rb=$(grep '^random ' "$b/boot-1/stdout")
    [ "$ra" != "$rb" ] || die "$g: same random bytes"
    da=$(field "$a/result.json" digest); db=$(field "$b/result.json" digest)
    [ "$da" != "$db" ] || die "$g: same digest"
    echo "$g: seeds differ ($ra / $rb)"
done
