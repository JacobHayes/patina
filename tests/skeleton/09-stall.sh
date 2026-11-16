# 9. A thread spinning without a syscall while another waits (spinpoints count, which a spin
# probe cannot preempt) ends unsupported, stop compute-stall, within stall-ms 500 plus 2.5 s,
# and leaves no process behind.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
out=$RUNS/09-stall
t0=$(date +%s%N)
timeout 8 "$PATINA" run --seed 1 --config "$("$PATINA_CFG" stall-ms=500)" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- /guest/spinpoints count || true
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
[ "$(field "$out/result.json" outcome)/$(field "$out/result.json" stop)" = unsupported/compute-stall ] || die "outcome $(field "$out/result.json" outcome) $(field "$out/result.json" stop)"
[ "$ms" -le 3000 ] || die "took $ms ms"
# No process of this run is left (launcher, bwrap, supervisor or guest; see tests/leftovers.py).
left=$(python3 -I "$(dirname "$0")/../leftovers.py" "$out" || true)
[ -z "$left" ] || die "processes left: $left"
echo "compute-stall after $ms ms, no process left"
