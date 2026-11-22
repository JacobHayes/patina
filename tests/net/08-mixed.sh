# 8. patina verify is identical on 2 seeds with mixed network faults (every net-* kind at once).
#@ tier=area budget=90
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-mixed; mkdir -p "$o"
F="--fault net-delay-ms=0..3 --fault net-chunk-max=700 --fault net-reset-permille=3 --fault net-connect-refuse-permille=50 --fault net-connect-timeout-permille=20 --fault net-blackout=20000+5000"
for seed in 1 2; do
    verify_ok "$o/chaos-$seed" "$seed" 3 $F -- /guest/sockets chaos 40 30
    echo "    $(grep chaos: "$o/chaos-$seed/run-0/boot-1/stdout"); faults injected $(field "$o/chaos-$seed/run-0/result.json" faults.injected), net $(field "$o/chaos-$seed/run-0/result.json" counters.net)"
done
# W8 itself under the same faults: identical, whatever the class.
verify_same "$o/w8" 1 3 $F -- /guest/sockets all
