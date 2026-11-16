# 7. A thread sleeping 1 s in a loop forever: outcome liveness at --vtime-limit-s 100, under 5 s wall.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
out=$RUNS/07-liveness
t0=$(date +%s%N)
PATINA_OPTS="--vtime-limit-s 100" patina_run "$out" 1 liveness
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
[ "$(field "$out/outcome.json" class)" = liveness ] || die "class $(field "$out/outcome.json" class)"
[ "$ms" -lt 5000 ] || die "took $ms ms"
echo "liveness after $ms ms wall"
