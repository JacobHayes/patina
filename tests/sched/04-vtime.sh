# 4. c-threads waits 30 virtual seconds; its own measurement of the timed wait is >= 30 s and
#    < 30.1 s. Three runs wait 90 virtual seconds, six times this script's budget: a real wait
#    fails it (no wall time is read).
#@ tier=quick
. "$(dirname "$0")/lib.inc"
for i in 1 2 3; do
    out=$RUNS/04-vtime/run$i
    patina_run "$out" 1 c-threads
    check_result "$out" c-threads
    ns=$(awk '$1 == "timedwait" {print $5}' "$out/inc-0/stdout")
    [ "$ns" -ge 30000000000 ] && [ "$ns" -lt 30100000000 ] || die "timed wait measured $ns ns"
    echo "run $i: wall $(field "$out/result.json" wall_ms) ms, timed wait measured $ns ns, $(grep virtual "$out/inc-0/stdout")"
done
