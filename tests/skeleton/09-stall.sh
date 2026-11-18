# 9. A thread spinning without a syscall while another waits (spinpoints count, which a spin
# probe cannot preempt) ends unsupported, stop compute-stall, after stall-ms 500 of the
# spinner's CPU time: the whole run uses at least that and under 2.5 s more CPU time (CPU
# time, which host load does not stretch, as it does wall time: the wall-time limit is only a
# safety net, as in patina_run). Leaves no process behind.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
out=$RUNS/09-stall
ms=$(python3 -I "$(dirname "$0")/../cpu-ms.py" timeout 120 "$PATINA" run --seed 1 --config "$("$PATINA_CFG" stall-ms=500)" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- /guest/spinpoints count)
[ "$(field "$out/result.json" outcome)/$(field "$out/result.json" stop)" = unsupported/compute-stall ] || die "outcome $(field "$out/result.json" outcome) $(field "$out/result.json" stop)"
[ "$ms" -ge 500 ] && [ "$ms" -le 3000 ] || die "used $ms ms of CPU time"
# No process of this run is left (launcher, bwrap, supervisor or guest; see tests/leftovers.py).
left=$(python3 -I "$(dirname "$0")/../leftovers.py" "$out" || true)
[ -z "$left" ] || die "processes left: $left"
echo "compute-stall after $ms ms of CPU time, no process left"
