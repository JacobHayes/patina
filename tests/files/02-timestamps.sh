# 2. Timestamp ordering: tsorder natively on a tmpfs with 20 ms between operations, and under
#    patina; the relation (<, =, >) of every pair of (file, field) records must match.
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/02-timestamps
mkdir -p "$o"
native "$o/native" -- /guest/tsorder 20 || die "native tsorder exit $?"
timeout 120 "$PATINA" run --seed 1 --out "$o/patina" --mount "$PATINA_GUESTS":/guest:copy -- /guest/tsorder 0 >/dev/null
[ "$(field "$o/patina/result.json" outcome)" = ok ] || die "patina tsorder: $(field "$o/patina/result.json" outcome)"
python3 -I "$LIB/ts_compare.py" "$o/native/stdout" "$o/patina/inc-0/stdout" || die "orderings differ"
