# 2. A part not ported yet ends the run unsupported, stop arm64-unported, naming the part: the
# same way twice. (A program that starts a thread reaches the clone trampolines.)
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
for k in a b; do
    prun "$RUNS/$k" --seed 1 -- "$PATINA_GUESTS/c-threads"
    [ "$(stop "$RUNS/$k")" = "unsupported arm64-unported" ] || die "$k: $(stop "$RUNS/$k"): $(tail -2 "$RUNS/$k.txt")"
    field "$RUNS/$k/result.json" message | grep -qw threads || die "$k: the message does not name threads"
done
[ "$(field "$RUNS/a/result.json" digest)" = "$(field "$RUNS/b/result.json" digest)" ] || die "digests differ between repeats"
field "$RUNS/a/result.json" message
