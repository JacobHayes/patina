# 7. A thread sleeping 1 s in a loop forever: outcome liveness at --time-limit 100. The 100
# virtual seconds are several times this script's budget: a real wait fails it.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
out=$RUNS/07-liveness
PATINA_OPTS="--time-limit 100" patina_run "$out" 1 liveness
[ "$(field "$out/result.json" outcome)/$(field "$out/result.json" stop)" = liveness/time-limit ] || die "outcome $(field "$out/result.json" outcome) $(field "$out/result.json" stop)"
echo "liveness after $(field "$out/result.json" wall_ms) ms wall"
