# 1b. rdrand and rdseed (16/32/64-bit, an extended register, a 16-bit form keeping the upper
# bits) 100 times each: carry flag set, identical over 3 runs varying the core, different seeds
# give different values.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-rand
verify "$o/s1" 1 3 insn rand
grep -qx 'OK rand' "$o/s1/run-0/inc-0/stdout" || die "guest checks failed: $(grep FAIL "$o/s1/run-0/inc-0/stdout" | head -3)"
echo "patched $(field "$o/s1/run-0/outcome.json" counters.insn.patched_sites), emulated $(field "$o/s1/run-0/outcome.json" counters.insn.emulated)"
[ "$(field "$o/s1/run-0/outcome.json" counters.insn.emulated.rdrand)" -ge 400 ] || die "rdrand emulations"
[ "$(field "$o/s1/run-0/outcome.json" counters.insn.emulated.rdseed)" -ge 400 ] || die "rdseed emulations"
trim "$o/s1"
for s in 2 3; do
    patina_run "$o/seed-$s" "$s" insn rand
    grep -qx 'OK rand' "$o/seed-$s/inc-0/stdout" || die "seed $s: guest checks failed"
done
n=$(for s in 2 3; do sha256sum <"$o/seed-$s/inc-0/stdout"; done; sha256sum <"$o/s1/run-0/inc-0/stdout")
d=$(echo "$n" | sort -u | wc -l)
[ "$d" = 3 ] || die "seeds 1-3 gave $d distinct outputs"
echo "seeds 1, 2, 3: 3 distinct outputs"
