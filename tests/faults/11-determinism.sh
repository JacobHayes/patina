# 11. Determinism with faults on: patina verify --runs 3 --vary cpu,load,sandbox identical
# for error injection, short transfers and crash and restart, seed 1 (the evidence tier's
# matrix covers volume).
#@ tier=quick budget=30 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
for seed in 1; do
    verify "$RUNS/11/errors-$seed" $seed 3 cpu,load,sandbox --fault fs-error-permille=100 -- /guest/io-errors tally
    verify "$RUNS/11/short-$seed" $seed 3 cpu,load,sandbox --fault fs-short-permille=200 -- /guest/short correct
    verify "$RUNS/11/crash-$seed" $seed 3 cpu,load,sandbox --crash machine:20 -- /guest/ack-log correct
    echo "seed $seed: errors $(field "$RUNS/11/errors-$seed/run-0/result.json" digest)," \
        "short $(field "$RUNS/11/short-$seed/run-0/result.json" digest)," \
        "crash $(field "$RUNS/11/crash-$seed/run-0/result.json" digest) ($(field "$RUNS/11/crash-$seed/run-0/result.json" incarnations) incarnations): 3 runs identical"
    rm -rf "$RUNS/11/errors-$seed" "$RUNS/11/short-$seed" "$RUNS/11/crash-$seed"
done
