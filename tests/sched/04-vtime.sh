# 4. c-threads waits 30 virtual seconds, finishes in under 5 s wall; its own measurement
#    of the timed wait is >= 30 s and < 30.1 s.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
for i in 1 2 3; do
    out=$RUNS/04-vtime/run$i
    t0=$(date +%s%N)
    patina_run "$out" 1 c-threads
    t1=$(date +%s%N)
    ms=$(( (t1 - t0) / 1000000 ))
    check_result "$out" c-threads
    ns=$(awk '$1 == "timedwait" {print $5}' "$out/inc-0/stdout")
    [ "$ns" -ge 30000000000 ] && [ "$ns" -lt 30100000000 ] || die "timed wait measured $ns ns"
    [ "$ms" -lt 5000 ] || die "took $ms ms wall"
    echo "run $i: wall $ms ms (patina run, whole command), timed wait measured $ns ns, $(grep virtual "$out/inc-0/stdout")"
done
