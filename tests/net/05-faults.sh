# 5. Each network fault has a scenario that passes with the fault and fails without it.
#@ tier=quick budget=30 slots=0.5
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
echo "net-chunk-max=1: naive receiver fails, passes without; correct receiver: $(grep 'correct receiver' "$o/chunk-correct-on/boot-1/stdout")"
# Splitting is bounded: the head of each write is cut into at most four pieces and the rest
# arrives whole, so 5 messages of 100 bytes take 25 reads, and 4 MiB at one-byte pieces costs
# a few deliveries per write, not one per byte.
grep -q ' in 25 reads' "$o/chunk-correct-on/boot-1/stdout" || die "split: $(cat "$o/chunk-correct-on/boot-1/stdout")"
run_ok "$o/xfer" 1 --fault net-chunk-max=1 -- /guest/sockets xfer 4096
c=$(net "$o/xfer" chunks)
[ "$c" -lt 10000 ] || die "4 MiB at net-chunk-max=1: $c deliveries"
echo "net-chunk-max=1: 4 MiB in $c deliveries"
# A reset is drawn once per connection, at a drawn send: at 1000 per mille a seed of 1-10
# resets the streaming client's connection mid-stream; without the fault that seed is clean.
s=0
for t in $(seq 1 10); do
    run "$o/reset-on-$t" "$t" --fault net-reset-permille=1000 -- /guest/sockets reset reset >/dev/null
    [ "$(field "$o/reset-on-$t/result.json" outcome)" = ok ] && { s=$t; break; }
done
[ "$s" != 0 ] || die "net-reset-permille=1000: no seed of 1-10 reset the stream"
run_fails "$o/reset-off" "$s" -- /guest/sockets reset reset
awk '/reset|ECONN|Connection/ && n++ < 3' "$o/reset-on-$s/boot-1/stdout"
pair refuse net-connect-refuse-permille=1000 connect refused
pair timeout net-connect-timeout-permille=1000 connect timeout
grep -h 'connect ->' "$o/timeout-on/boot-1/stdout"
pair blackout net-blackout=5000+10000 partition partitioned
grep -h 'application timeout\|tick 05' "$o/blackout-on/boot-1/stdout"
# net-reset is drawn once per connection, so its attribution counts connections, and no
# connection is reset twice: at 1000 per mille, injected never exceeds eligible.
for s in $(seq 1 20); do run "$o/rate-$s" "$s" --fault net-reset-permille=1000 -- /guest/sockets all >/dev/null; done
python3 -I - "$o"/rate-*/result.json <<'PY' || exit 1
import json, sys
inj = elig = 0
for p in sys.argv[1:]:
    r = json.load(open(p))
    c = r["faults"]["counts"]["net-reset"]
    if not c["injected"] <= c["eligible"] == r["counters"]["net"]["connections"]:
        sys.exit("FAIL: %s: net-reset %s" % (p, c))
    inj, elig = inj + c["injected"], elig + c["eligible"]
print("net-reset over 20 seeds: %d injected of %d connections" % (inj, elig))
if inj < 10:
    sys.exit("FAIL: net-reset injected %d times over 20 seeds at 1000 per mille" % inj)
PY
