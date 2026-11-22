# 4. F3 (flush worker dies on EIO, writers sleep forever). time-limit 400: the outcome is
# liveness, the parked thread is in a sleep whose deadline is within 100 ms of the limit (the
# write-stall loop's 100 ms sleep); the 400 virtual seconds are many times this script's
# budget, so a real wait fails it. Seeds 1-500 are searched, 100 at a time, stopping at the
# block that holds one: about two seeds in a hundred reach it, which ones depending on the
# host's CPU (also under [sched] preempt = "traps", used here, as for F4, for its cheaper
# runs); the first liveness seed whose log shows the flush worker crash must show all of that.
# The rate depends on the schedule and the guest build, so this is an area check, not a quick
# one.
#@ tier=area budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
found= all=
for b in 1-100 101-200 201-300 301-400 401-500; do
    seeds=$(matches f3 'parked: .*wait=sleep deadline=' fjall-harness "$b" -- --env FJ_N=1000 --faults buggify \
        --env FJ_LOG=2 --env FJ_WIPE_PARTIAL=1 --config "$("$PATINA_CFG" time-limit=400 preempt=traps)" --fault fs-error-permille=3 \
        --fault crash-permille=2 -- /guest/fjall-harness-debug)
    all="$all $seeds"
    for s in $seeds; do
        grep -q 'Worker #0 crashed' "$RUNS/f3/run-$s"/boot-*/stderr && { found=$s; break; }
    done
    [ -z "$found" ] || break
done
[ -n "$found" ] || die "F3: no liveness seed of 1-${b#*-} with a flush worker crash (liveness seeds: $(echo $all))"
o=$RUNS/f3/run-$found
[ "$(field "$o/result.json" outcome)" = liveness ] || die "F3: $(field "$o/result.json" outcome) $(field "$o/result.json" message)"
d=$(field "$o/result.json" message)
dl=$(echo "$d" | sed -n 's/.*wait=sleep deadline=\([0-9]*\).*/\1/p')
[ -n "$dl" ] || die "F3: no sleeping thread in the detail: $d"
limit=$(( (100 + 400) * 1000000000 ))
[ "$dl" -gt "$limit" ] && [ "$dl" -le $((limit + 100000000)) ] || die "F3: sleep deadline $dl not within 100 ms past the limit"
echo "F3: liveness seeds $(echo $all) of 1-${b#*-}; seed $found: $d; $(field "$o/result.json" wall_ms) ms wall"
