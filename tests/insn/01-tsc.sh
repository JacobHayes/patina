# 1a. rdtsc and rdtscp 1,000 times interleaved with clock_gettime: values strictly increase,
# lie between the surrounding clock reads (3 ticks per virtual ns), rdtscp's aux is 0; identical
# over 3 runs varying the core. A guest that asks for PR_TSC_SIGSEGV gets the signal.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-tsc
verify "$o/v" 1 3 insn tsc
grep -qx 'OK tsc' "$o/v/run-0/inc-0/stdout" || die "guest checks failed: $(grep FAIL "$o/v/run-0/inc-0/stdout" | head -3)"
[ "$(field "$o/v/run-0/outcome.json" emulated.rdtscp)" -ge 1000 ] || die "fewer than 1000 rdtscp emulations"
[ "$(field "$o/v/run-0/outcome.json" emulated.rdtsc)" -ge 1000 ] || die "fewer than 1000 rdtsc emulations"
n=$("$PATINA" log dump "$o/v/run-0/inc-0/boundary.log" | grep -c ' insn ')
echo "insn records in the boundary log: $n; emulated $(field "$o/v/run-0/outcome.json" emulated)"
[ "$n" -ge 2000 ] || die "only $n insn records"
trim "$o/v"
patina_run "$o/tscsig" 1 insn tscsig
[ "$(field "$o/tscsig/outcome.json" class)" = ok ] || die "tscsig: $(field "$o/tscsig/outcome.json" detail)"
grep -qx 'OK tscsig' "$o/tscsig/inc-0/stdout" || die "tscsig: $(cat "$o/tscsig/inc-0/stdout")"
echo "PR_SET_TSC(PR_TSC_SIGSEGV) by the guest: rdtsc delivered SIGSEGV to it; PR_GET_TSC virtual"
