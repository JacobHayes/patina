# Hazard: a ud2 the guest itself contains goes to the guest as SIGILL (only addresses in the
# side table are emulated); the runtime's own code contains no rdtsc, rdtscp, rdrand or rdseed.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-guest-ud2
patina_run "$o/ud2" 1 insn ud2 || true
[ "$(field "$o/ud2/outcome.json" outcome)" = crash ] && [ "$(field "$o/ud2/outcome.json" guest.signal)" = 4 ] ||
    die "guest ud2: $(field "$o/ud2/outcome.json" outcome) $(field "$o/ud2/outcome.json" message)"
echo "guest ud2: crash, signal 4"
python3 -I "$HERE/lib/census.py" "$RT_BIN" >"$o/rt-census.txt"
for k in scan rdtsc rdtscp; do
    r=$(awk -F'\t' -v k="$k" '$1 == "count" && $3 == k {print $4}' "$o/rt-census.txt")
    echo "runtime $k: $r"
    [ "$r" = "real=0" ] || die "the runtime executes $k"
done
