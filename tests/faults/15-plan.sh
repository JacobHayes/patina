# 15. The fault plan comes from the seed. Under --faults disk two seeds resolve different
# rates in run.json and one seed twice the same. Plan independence (the coupling where one
# setting's draw moved another's): adding --fault net-chunk-max=1..4 to a run without sockets
# (ack-log, --faults disk --crash machine:0..30) leaves every other resolved value and the whole
# boundary log equal. A net-partition window given as ranges (START 0..60000, LENGTH
# 1000..10000 ms) is drawn per seed within them: seeds 1-4 resolve windows inside the ranges,
# not all the same. max-incarnations on the command line bounds the restarts: a crash at
# every crash point gives 4 incarnations by default and 2 with --fault max-incarnations=2.
#@ tier=quick budget=20
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/15
plan() { python3 -I -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["faults"], sort_keys=True))' "$1/run.json"; }
for s in 1 2; do
    run "$d/disk-$s" $s --faults disk -- /guest/io-errors tally
done
run "$d/disk-1-again" 1 --faults disk -- /guest/io-errors tally
echo "seed 1: $(plan "$d/disk-1")"
echo "seed 2: $(plan "$d/disk-2")"
p1=$(plan "$d/disk-1"); p1again=$(plan "$d/disk-1-again"); p2=$(plan "$d/disk-2")
[ "$p1" = "$p1again" ] || die "one seed resolved two plans"
[ "$p1" != "$p2" ] || die "two seeds resolved the same plan"
lhs=$(field "$d/disk-1/result.json" digest); rhs=$(field "$d/disk-1-again/result.json" digest)
[ "$lhs" = "$rhs" ] || die "one seed, two digests"
found=""
for s in 1 2 3 4 5 6 7 8; do
    run "$d/base-$s" $s --faults disk --crash machine:0..30 -- /guest/ack-log correct
    run "$d/more-$s" $s --faults disk --crash machine:0..30 --fault net-chunk-max=1..4 -- /guest/ack-log correct
    python3 -I - "$d/base-$s" "$d/more-$s" <<'PY' || exit 1
import json, sys
a, b = (json.load(open(p + "/run.json"))["faults"] for p in sys.argv[1:3])
extra = {k: v for k, v in b.items() if k not in a}
if {k: v for k, v in b.items() if k in a} != a or list(extra) != ["net-chunk-max"]:
    sys.exit("FAIL: adding net-chunk-max moved the plan: %s vs %s" % (a, b))
PY
    lhs=$(field "$d/base-$s/result.json" digest); rhs=$(field "$d/more-$s/result.json" digest)
    [ "$lhs" = "$rhs" ] \
        || die "seed $s: net-chunk-max on a run without sockets changed the boundary log ($("$PATINA" log diff "$d/base-$s/inc-0/boundary.log" "$d/more-$s/inc-0/boundary.log" | head -1))"
    if [ "$(field "$d/base-$s/result.json" faults.injected)" -gt 0 ]; then found=$s; break; fi
done
[ -n "$found" ] || die "no seed of 1-8 injected a fault"
echo "seed $found: plan $(plan "$d/base-$found"); adding net-chunk-max=1..4 (resolved $(field "$d/more-$found/run.json" faults.net-chunk-max)) left the plan and the log (digest $(field "$d/base-$found/result.json" digest), $(field "$d/base-$found/result.json" faults.injected) faults) unchanged"
wins=""
for s in 1 2 3 4; do
    run "$d/part-$s" $s --fault net-partition=0..60000+1000..10000 -- /guest/io-errors tally
    w=$(field "$d/part-$s/run.json" faults.net-partition)
    python3 -I -c 'import sys; a, b = map(int, sys.argv[1].split("+")); sys.exit(not (0 <= a <= 60000 and 1000 <= b <= 10000))' "$w" \
        || die "seed $s: net-partition window $w outside 0..60000+1000..10000"
    wins="$wins $w"
done
[ "$(printf '%s\n' $wins | sort -u | wc -l)" -gt 1 ] || die "net-partition: one window for every seed:$wins"
echo "net-partition=0..60000+1000..10000 resolved per seed:$wins"
for m in "" 2; do
    run "$d/inc-$m" 1 --crash process:1000 ${m:+--fault max-incarnations=$m} -- /guest/ack-log correct
    echo "max-incarnations ${m:-default}: $(field "$d/inc-$m/result.json" incarnations) incarnations"
done
[ "$(field "$d/inc-/result.json" incarnations)" = 4 ] && [ "$(field "$d/inc-2/result.json" incarnations)" = 2 ] ||
    die "max-incarnations: $(field "$d/inc-/result.json" incarnations) by default, $(field "$d/inc-2/result.json" incarnations) with 2"
