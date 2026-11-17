# 4. F3 (flush worker dies on EIO, writers sleep forever). --time-limit 400: the outcome is
# liveness, the parked thread is in a sleep whose deadline is within 100 ms of the limit (the
# write-stall loop's 100 ms sleep), in bounded wall time. Seeds 1-100 are searched (a few
# percent reach it); the first liveness seed whose log shows the flush worker crash must
# show all of that. The rate depends on the schedule and the guest build, so this is an area
# check, not a quick one.
#@ tier=area budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
seeds=$(matches f3 'parked: .*wait=sleep deadline=' fjall-harness 1-100 -- --env FJ_N=1000 --buggify \
    --env FJ_LOG=2 --env FJ_WIPE_PARTIAL=1 --time-limit 400 --fault fs-error-permille=3 --crash machine:2 \
    -- /guest/fjall-harness-debug)
found=
for s in $seeds; do
    grep -q 'Worker #0 crashed' "$RUNS/f3/run-$s"/inc-*/stderr && { found=$s; break; }
done
[ -n "$found" ] || die "F3: no liveness seed of 1-100 with a flush worker crash (liveness seeds: $(echo $seeds))"
o=$RUNS/f3/run-$found
[ "$(field "$o/result.json" outcome)" = liveness ] || die "F3: $(field "$o/result.json" outcome) $(field "$o/result.json" message)"
d=$(field "$o/result.json" message)
dl=$(echo "$d" | sed -n 's/.*wait=sleep deadline=\([0-9]*\).*/\1/p')
[ -n "$dl" ] || die "F3: no sleeping thread in the detail: $d"
limit=$(( (100 + 400) * 1000000000 ))
[ "$dl" -gt "$limit" ] && [ "$dl" -le $((limit + 100000000)) ] || die "F3: sleep deadline $dl not within 100 ms past the limit"
ms=$(field "$o/result.json" wall_ms)
[ "$ms" -lt 60000 ] || die "F3: $ms ms wall"
echo "F3: liveness seeds $(echo $seeds) of 1-100; seed $found: $d; $ms ms wall"
