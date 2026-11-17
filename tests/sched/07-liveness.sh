# 7. A thread sleeping 1 s in a loop forever: outcome liveness at --time-limit 100, in less
# wall time than the 100 virtual seconds (no real wait).
#@ tier=quick
. "$(dirname "$0")/lib.inc"
out=$RUNS/07-liveness
t0=$(date +%s%N)
PATINA_OPTS="--time-limit 100" patina_run "$out" 1 liveness
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
[ "$(field "$out/result.json" outcome)/$(field "$out/result.json" stop)" = liveness/time-limit ] || die "outcome $(field "$out/result.json" outcome) $(field "$out/result.json" stop)"
[ "$ms" -lt 100000 ] || die "took $ms ms"
echo "liveness after $ms ms wall"
