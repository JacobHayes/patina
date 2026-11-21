# 5. Delay: fs-delay-permille=1000: each of 100 writes is delayed by 0..10 ms of virtual time,
# so they take more than 100 ms and at most 1.1 s of it, and the run without the fault takes
# a small part of that (the delay is virtual: no wall time is read).
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/05/delay
run "$o" 1 --fault fs-delay-permille=1000 -- /guest/delay
run "$o-off" 1 -- /guest/delay
v=$(awk '{print $4}' "$o/inc-0/stdout")
off=$(awk '{print $4}' "$o-off/inc-0/stdout")
echo "100 writes: virtual ${v} ms (${off} ms without the fault), wall $(field "$o/result.json" wall_ms) ms (whole run)"
[ "$v" -gt 100 ] && [ "$v" -le 1100 ] || die "virtual time $v ms"
[ "$off" -lt $((v / 2)) ] || die "virtual time without the fault $off ms, with it $v ms"
