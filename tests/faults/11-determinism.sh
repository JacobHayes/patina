# 11. Determinism with faults on: patina verify --runs 3 --vary cpu,load,sandbox identical
# for error injection, short transfers and crash and restart, seed 1, the three at once (the
# evidence tier's matrix covers volume).
#@ tier=quick budget=30 slots=3
. "$(dirname "$0")/lib/common.inc"
seed=1
verify "$RUNS/11/errors" $seed 3 cpu,load,sandbox --fault fs-error-permille=100 -- /guest/io-errors tally >"$RUNS/11-errors.txt" &
e=$!
verify "$RUNS/11/short" $seed 3 cpu,load,sandbox --fault fs-short-permille=200 -- /guest/short correct >"$RUNS/11-short.txt" &
s=$!
verify "$RUNS/11/crash" $seed 3 cpu,load,sandbox --fault crash-permille=20 -- /guest/ack-log correct >"$RUNS/11-crash.txt" &
c=$!
for p in $e $s $c; do wait $p || { cat "$RUNS"/11-*.txt; exit 1; }; done
echo "seed $seed: errors $(field "$RUNS/11/errors/run-0/result.json" digest)," \
    "short $(field "$RUNS/11/short/run-0/result.json" digest)," \
    "crash $(field "$RUNS/11/crash/run-0/result.json" digest) ($(field "$RUNS/11/crash/run-0/result.json" incarnations) incarnations): 3 runs identical"
rm -rf "${RUNS:?}/11"
