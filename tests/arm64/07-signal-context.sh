# 7. A signal frame that would hold state Patina does not build (SME's ZA array in use,
# streaming mode) ends the run unsupported, stop signal-context, naming the record, the same
# way twice. Only on hosts with SME; elsewhere there is nothing to check.
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
grep -qw sme /proc/cpuinfo || { echo "no SME on this host: nothing to check"; exit 0; }
for m in za sm; do
    for k in a b; do
        prun "$RUNS/$m$k" --seed 1 -- "$PATINA_GUESTS/sme-state" "$m"
        [ "$(stop "$RUNS/$m$k")" = "unsupported signal-context" ] || die "$m $k: $(stop "$RUNS/$m$k"): $(tail -2 "$RUNS/$m$k.txt")"
    done
    [ "$(field "$RUNS/${m}a/result.json" digest)" = "$(field "$RUNS/${m}b/result.json" digest)" ] || die "$m: digests differ between repeats"
    echo "$m: $(field "$RUNS/${m}a/result.json" message)"
done
