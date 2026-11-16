# 5. Each network fault has a scenario that passes with the fault and fails without it.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-faults; mkdir -p "$o"
# pair NAME FAULT ARGS...: ok with --fault FAULT, guest failure without.
pair() {
    n=$1; f=$2; shift 2
    run_ok "$o/$n-on" 1 --fault "$f" -- /guest/sockets "$@"
    run_fails "$o/$n-off" 1 -- /guest/sockets "$@"
    echo "$f: $*: passes with the fault, fails without; faults injected $(field "$o/$n-on/outcome.json" faults.injected), net $(field "$o/$n-on/outcome.json" counters.net)"
}
# A receiver that assumes one read per message breaks under 1-byte chunks.
run_fails "$o/chunk-naive-on" 1 --fault net-chunk-max=1 -- /guest/sockets chunk naive
run_ok "$o/chunk-naive-off" 1 -- /guest/sockets chunk naive
run_ok "$o/chunk-correct-on" 1 --fault net-chunk-max=1 -- /guest/sockets chunk correct
echo "net-chunk-max=1: naive receiver fails, passes without; correct receiver: $(grep 'correct receiver' "$o/chunk-correct-on/inc-0/stdout")"
[ "$(net "$o/chunk-correct-on" chunks)" -ge 500 ] || die "chunks"
pair reset net-reset-permille=200 reset reset
grep -h 'reset\|ECONN\|Connection' "$o/reset-on/inc-0/stdout" | head -3
pair refuse net-connect-refuse-permille=1000 connect refused
pair timeout net-connect-timeout-permille=1000 connect timeout
grep -h 'connect ->' "$o/timeout-on/inc-0/stdout"
pair partition net-partition=5000..15000 partition partitioned
grep -h 'application timeout\|tick 05' "$o/partition-on/inc-0/stdout"
pair halfclose net-halfclose-delay-ms=2000..2000 halfclose-delay 2000
grep -h 'EOF reached' "$o/halfclose-on/inc-0/stdout"
