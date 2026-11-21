# Spin-waits in rebuilt code need neither `pause` nor a spin probe (stall-ms=1000):
#  a. `spinpoints count` (a wait that counts its iterations: no fixed point, so stock it ends
#     compute-stall) ends ok on seeds 1-3 with no spin found;
#  b. the spin table's own spin lock waiting without a spin hint (`spinwait own-spin-nohint`)
#     ends ok on seeds 1-3 with pause points and spin probes off;
#  c. both, with switches off (compute-gap=0), still end ok on seed 1 with no spin found: the
#     cell runs out every 2^22 events and yields.
#@ tier=quick budget=20 slots=1.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-spin
mkdir -p "$o"
# Test inputs (AGENTS.md): stall-ms 1000; the locks also without pause points and spin probes.
export PATINA_TEST_STALL_MS=1000
# --timeout: a run that cannot end by itself ends here, not at the script's budget.
for s in 1 2 3; do
    prun "$o/count-$s" "$s" --timeout 10 -- /guest/compute/spinpoints count &
    PATINA_TEST_PAUSE_POINTS=0 PATINA_TEST_SPIN_PROBES=0 prun "$o/lock-$s" "$s" --timeout 10 -- /guest/compute/spinwait own-spin-nohint &
done
prun "$o/count-0" 1 --timeout 10 --fault compute-gap=0 -- /guest/compute/spinpoints count &
PATINA_TEST_PAUSE_POINTS=0 PATINA_TEST_SPIN_PROBES=0 prun "$o/lock-0" 1 --timeout 10 --fault compute-gap=0 -- /guest/compute/spinwait own-spin-nohint &
wait
for s in 1 2 3; do
    [ "$(field "$o/count-$s/result.json" outcome)" = ok ] || die "a. spinpoints count seed $s: $(res "$o/count-$s")"
    [ "$(field "$o/count-$s/result.json" counters.sched.spin_found)" = 0 ] || die "a. seed $s needed a spin probe"
    [ "$(field "$o/lock-$s/result.json" outcome)" = ok ] || die "b. spinwait own-spin-nohint seed $s: $(res "$o/lock-$s")"
done
echo "a. counting spin-wait: ok on seeds 1-3, no spin probe found one; compute switches on seed 1: $(field "$o/count-1/result.json" compute.switches)"
echo "b. spin lock without pause, pause points and probes off: ok on seeds 1-3; compute switches on seed 1: $(field "$o/lock-1/result.json" compute.switches)"
for r in count-0 lock-0; do
    [ "$(field "$o/$r/result.json" outcome)" = ok ] || die "c. $r at compute-gap=0: $(res "$o/$r")"
    [ "$(field "$o/$r/result.json" counters.sched.spin_found)" = 0 ] || die "c. $r at compute-gap=0 needed a spin probe"
done
echo "c. compute-gap=0: both ok, no spin probe found one; yields: $(field "$o/count-0/result.json" compute.switches) and $(field "$o/lock-0/result.json" compute.switches)"
