# 1. c-threads, rs-threads, order: outcome ok and correct results (seed 1).
#@ tier=quick
. "$(dirname "$0")/lib.inc"
for g in $GUESTS; do
    out=$RUNS/01-ok/$g
    patina_run "$out" 1 "$g"
    check_result "$out" "$g"
    echo "$g: ok, results correct, digest $(field "$out/result.json" digest), switches $(field "$out/result.json" sched.switches)"
done
