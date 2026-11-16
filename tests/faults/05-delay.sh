# 5. Delay: delay-permille=1000 delay-max-ms=50: 100 writes take > 1 s of virtual time and
# less than half that in wall time (no real wait).
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/05/delay
run "$o" 1 --fault delay-permille=1000 --fault delay-max-ms=50 -- /guest/delay
v=$(awk '{print $4}' "$o/inc-0/stdout")
w=$(field "$o/outcome.json" wall_ms)
echo "100 writes: virtual ${v} ms, wall ${w} ms (whole run)"
[ "$v" -gt 1000 ] || die "virtual time $v ms"
[ $((w * 2)) -lt "$v" ] || die "wall time $w ms against $v virtual ms"
