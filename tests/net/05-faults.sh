# 5. Each network fault has a scenario that passes with the fault and fails without it.
#@ tier=quick budget=30 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-faults; mkdir -p "$o"
# pair NAME FAULT ARGS...: ok with --fault FAULT, guest failure without.
pair() {
    n=$1; f=$2; shift 2
    run_ok "$o/$n-on" 1 --fault "$f" -- /guest/sockets "$@"
    run_fails "$o/$n-off" 1 -- /guest/sockets "$@"
    echo "$f: $*: passes with the fault, fails without; faults injected $(field "$o/$n-on/result.json" faults.injected), net $(field "$o/$n-on/result.json" counters.net)"
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
# net-reset's attribution counts what it is drawn on (each read of sent data), so over a seed
# range injected / eligible is near the rate (500 permille), not one reset per connection.
for s in $(seq 1 20); do run "$o/rate-$s" "$s" --fault net-reset-permille=500 -- /guest/sockets all >/dev/null; done
python3 -I - "$o"/rate-*/result.json <<'PY' || exit 1
import json, sys
inj = elig = 0
for p in sys.argv[1:]:
    c = json.load(open(p))["faults"]["counts"]["net-reset"]
    if c["injected"] > c["eligible"]:
        sys.exit("FAIL: %s: net-reset %s" % (p, c))
    inj, elig = inj + c["injected"], elig + c["eligible"]
print("net-reset over 20 seeds: %d injected of %d eligible" % (inj, elig))
if not (inj >= 10 and 0.3 <= inj / elig <= 0.7):
    sys.exit("FAIL: net-reset injected %d of %d eligible at 500 permille" % (inj, elig))
PY
