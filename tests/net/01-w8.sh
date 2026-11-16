# 1. W8 `sockets` (faults off) is ok; patina verify --runs 3 --vary cpu,load,sandbox is identical
#    (seed 1); 6 seeds give at least 3 distinct digests. (the recorded run: 5 seeds x 20 runs and
#    10 seeds; the evidence tier's matrix has W8 as a cell.)
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-w8; mkdir -p "$o"
verify_ok "$o/v1" 1 3 -- /guest/sockets all
for seed in 2 3 4 5 6; do
    run_ok "$o/r$seed" "$seed" -- /guest/sockets all
    rm -f "$o/r$seed/inc-0/boundary.log"
done
d=$( (field "$o/v1/run-0/outcome.json" digest
      for s in 2 3 4 5 6; do field "$o/r$s/outcome.json" digest; done) | sort -u | wc -l)
echo "distinct digests over 6 seeds: $d"
[ "$d" -ge 3 ] || die "only $d distinct digests"
