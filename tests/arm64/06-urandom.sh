# 6. Bytes read from /dev/urandom come from the seed: two runs of one seed print the same.
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
for k in a b; do
    prun "$RUNS/$k" --seed 1 -- "$PATINA_GUESTS/urandom"
    [ "$st" = 0 ] || die "$k: exit $st ($(tail -2 "$RUNS/$k.txt"))"
done
cmp -s "$RUNS/a/inc-0/stdout" "$RUNS/b/inc-0/stdout" || die "the bytes differ: $(cat "$RUNS/a/inc-0/stdout") vs $(cat "$RUNS/b/inc-0/stdout")"
cat "$RUNS/a/inc-0/stdout"
