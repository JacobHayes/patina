# 1a. The counter 1,000 times interleaved with clock_gettime (x86: rdtsc and rdtscp; arm64:
# CNTVCT_EL0, and CNTVCTSS_EL0 where the CPU has it, around a 1 ms sleep too): values strictly
# increase, lie between the surrounding clock reads (x86: 3 ticks per virtual ns, rdtscp's aux
# is 0; arm64: 1 tick per ns, CNTFRQ_EL0 = 1e9); identical over 3 runs varying the core. A guest
# that asks for PR_TSC_SIGSEGV gets the signal.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-tsc
case $ARCH in
    x86_64) reads="rdtsc rdtscp" ;;
    *) reads="cntvct" ;;
esac
verify "$o/v" 1 3 insn tsc
grep -qx 'OK tsc' "$o/v/run-0/boot-1/stdout" || die "guest checks failed: $(grep FAIL "$o/v/run-0/boot-1/stdout" | head -3)"
for k in $reads; do
    [ "$(field "$o/v/run-0/result.json" "counters.insn.emulated.$k")" -ge 1000 ] || die "fewer than 1000 $k emulations"
done
n=$("$PATINA" inspect dump "$o/v/run-0/boot-1/boundary.log" | grep -c ' insn ')
echo "insn records in the boundary log: $n; emulated $(field "$o/v/run-0/result.json" counters.insn.emulated)"
[ "$n" -ge 2000 ] || die "only $n insn records"
trim "$o/v"
patina_run "$o/tscsig" 1 insn tscsig
[ "$(field "$o/tscsig/result.json" outcome)" = ok ] || die "tscsig: $(field "$o/tscsig/result.json" message)"
grep -qx 'OK tscsig' "$o/tscsig/boot-1/stdout" || die "tscsig: $(cat "$o/tscsig/boot-1/stdout")"
echo "PR_SET_TSC(PR_TSC_SIGSEGV) by the guest: the counter delivered SIGSEGV to it; PR_GET_TSC virtual"
