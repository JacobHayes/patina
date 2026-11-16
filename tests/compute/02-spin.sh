#!/bin/sh
# Spin-waits in rebuilt code need neither `pause` nor a spin probe (stall-ms=1000):
#  a. `spinpoints count` (a wait that counts its iterations: no fixed point, so stock it ends
#     compute-stall) ends ok on seeds 1-3 with no spin found;
#  b. the spin table's own spin lock with its `pause` taken out (`spinwait own-spin`) ends ok
#     on seeds 1-3 with pause points and spin probes off.
#@ tier=quick budget=20 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-spin
mkdir -p "$o"
on=$("$PATINA_CFG" stall-ms=1000)
off=$("$PATINA_CFG" stall-ms=1000 pause-points=false spin-probes=false)
# --timeout: a run that cannot end by itself ends here, not at the script's budget.
for s in 1 2 3; do
    prun "$o/count-$s" "$s" --timeout 10 --config "$on" -- /guest/compute/spinpoints count &
    prun "$o/lock-$s" "$s" --timeout 10 --config "$off" -- /guest/compute/spinwait own-spin &
done
wait
for s in 1 2 3; do
    [ "$(field "$o/count-$s/result.json" outcome)" = ok ] || die "a. spinpoints count seed $s: $(res "$o/count-$s")"
    [ "$(field "$o/count-$s/result.json" counters.sched.spin_found)" = 0 ] || die "a. seed $s needed a spin probe"
    [ "$(field "$o/lock-$s/result.json" outcome)" = ok ] || die "b. spinwait own-spin seed $s: $(res "$o/lock-$s")"
done
echo "a. counting spin-wait: ok on seeds 1-3, no spin probe found one; compute switches on seed 1: $(field "$o/count-1/result.json" compute.switches)"
echo "b. spin lock without pause, pause points and probes off: ok on seeds 1-3; compute switches on seed 1: $(field "$o/lock-1/result.json" compute.switches)"
