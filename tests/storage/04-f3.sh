# 4. F3 (flush worker dies on EIO, writers sleep forever). --time-limit 400: the
# outcome is liveness, the parked thread is in a sleep whose deadline is within 100 ms of
# the limit (the write-stall loop's 100 ms sleep), in bounded wall time. Seed 40 of 600.
# The seeds depend on the host's libc and CPU (they were found on the development host), so
# this is an area check, not a quick one.
#@ tier=area budget=15
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/f3-40
run fjall-harness "$o" 40 --env FJ_N=1000 --env FJ_BUGGIFY=1 --env FJ_LOG=2 --env FJ_WIPE_PARTIAL=1 \
    --time-limit 400 --fault fs-error-permille=3 --crash machine:2 -- /guest/fjall-harness-debug
[ "$(field "$o/outcome.json" outcome)" = liveness ] || die "F3: $(field "$o/outcome.json" outcome) $(field "$o/outcome.json" message)"
d=$(field "$o/outcome.json" message)
dl=$(echo "$d" | sed -n 's/.*wait=sleep deadline=\([0-9]*\).*/\1/p')
[ -n "$dl" ] || die "F3: no sleeping thread in the detail: $d"
limit=$(( (100 + 400) * 1000000000 ))
[ "$dl" -gt "$limit" ] && [ "$dl" -le $((limit + 100000000)) ] || die "F3: sleep deadline $dl not within 100 ms past the limit"
grep -q 'Worker #0 crashed' "$o"/inc-*/stderr || die "F3: no flush worker crash in the log"
ms=$(field "$o/outcome.json" wall_ms)
[ "$ms" -lt 60000 ] || die "F3: $ms ms wall"
echo "F3 seed 40: liveness, $d; $ms ms wall"
