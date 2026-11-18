# 5. Delay: fs-delay-permille=1000 fs-delay-max-ms=1000: 100 writes take more than 30 s of virtual
# time, twice this script's budget, so a real wait would fail it (no wall time is read).
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/05/delay
run "$o" 1 --fault fs-delay-permille=1000 --fault fs-delay-max-ms=1000 -- /guest/delay
v=$(awk '{print $4}' "$o/inc-0/stdout")
echo "100 writes: virtual ${v} ms, wall $(field "$o/result.json" wall_ms) ms (whole run)"
[ "$v" -gt 30000 ] || die "virtual time $v ms"
