# 2. A call no ported part serves ends the run unsupported, stop arm64-unported, naming the call:
# the same way twice.
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
for k in a b; do
    prun "$RUNS/$k" --seed 1 -- "$PATINA_GUESTS/getppid" 1
    [ "$(stop "$RUNS/$k")" = "unsupported arm64-unported" ] || die "$k: $(stop "$RUNS/$k"): $(tail -2 "$RUNS/$k.txt")"
    field "$RUNS/$k/result.json" message | grep -qw getppid || die "$k: the message does not name getppid"
done
[ "$(field "$RUNS/a/result.json" digest)" = "$(field "$RUNS/b/result.json" digest)" ] || die "digests differ between repeats"
field "$RUNS/a/result.json" message
