# 1. fs-tour exercises every call of the classes and prints every value and buffer;
#    patina verify --runs 4 --vary cpu,load,aslr,sandbox identical (seed 1). (the recorded run: 20
#    runs x seeds 1-3; volume is the evidence tier's matrix, where fs-tour is a cell.)
#@ tier=quick budget=30
. "$(dirname "$0")/lib/common.inc"
verify_ok "$RUNS/01-fs-tour-1" 1 cpu,load,aslr,sandbox 4 -- /guest/fs-tour
o=$RUNS/01-fs-tour-1/run-0
echo "fs-tour: ok, $(field "$o/outcome.json" traps) traps, $(wc -l <"$o/inc-0/stdout") output lines; 4 runs identical"
