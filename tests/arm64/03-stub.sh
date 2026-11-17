# 3. Containment: program code that branches to the runtime's `svc #0` on its own stack makes a
# real call, and the stub's stack check ends the run unsupported, stop containment, before the
# program sees the answer; the same way twice.
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
for k in a b; do
    prun "$RUNS/$k" --seed 1 -- "$PATINA_GUESTS/stub-gadget"
    [ "$(stop "$RUNS/$k")" = "unsupported containment" ] || die "$k: $(stop "$RUNS/$k"): $(cat "$RUNS/$k/inc-0/stdout" 2>/dev/null) $(tail -2 "$RUNS/$k.txt")"
    [ ! -s "$RUNS/$k/inc-0/stdout" ] || die "$k: the program printed: $(cat "$RUNS/$k/inc-0/stdout")"
done
[ "$(field "$RUNS/a/result.json" digest)" = "$(field "$RUNS/b/result.json" digest)" ] || die "digests differ between repeats"
field "$RUNS/a/result.json" message
