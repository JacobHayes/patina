# 5. Each network fault has a scenario that passes with the fault and fails without it.
#@ tier=quick budget=30
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
# The pieces of a split delivery follow each other by microseconds, not each by a delivery
# delay: 500 one-byte pieces at net-delay-ms=10..10 take well under 500 x 10 ms, one read each.
run_ok "$o/gap" 1 --fault net-chunk-max=1 --fault net-delay-ms=10..10 -- /guest/sockets chunk correct
span=$("$PATINA" log events "$o/gap" | jq -s 'map(select(.t)) | last.t - first.t')
grep -q ' in 500 reads' "$o/gap/inc-0/stdout" && [ "$span" -lt 1000000000 ] || die "split delivery: $span ns; $(cat "$o/gap/inc-0/stdout")"
echo "net-chunk-max=1 at net-delay-ms=10..10: 500 one-byte reads in $((span / 1000000)) ms of virtual time"
[ "$(net "$o/chunk-correct-on" chunks)" -ge 500 ] || die "chunks"
pair reset net-reset-permille=200 reset reset
awk '/reset|ECONN|Connection/ && n++ < 3' "$o/reset-on/inc-0/stdout"
pair refuse net-connect-refuse-permille=1000 connect refused
pair timeout net-connect-timeout-permille=1000 connect timeout
grep -h 'connect ->' "$o/timeout-on/inc-0/stdout"
pair blackout net-blackout=5000+10000 partition partitioned
grep -h 'application timeout\|tick 05' "$o/blackout-on/inc-0/stdout"
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
