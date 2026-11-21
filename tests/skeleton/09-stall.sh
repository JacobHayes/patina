# 9. A thread spinning without a syscall while another waits (spinpoints count, which a spin
# probe cannot preempt) ends unsupported, stop compute-stall, after stall-ms 500 of the
# spinner's CPU time: the whole run uses at least that and under 2.5 s more CPU time (CPU
# time, which host load does not stretch, as it does wall time: the wall-time limit is only a
# safety net, as in patina_run). The message names where the spinner was, by function and file
# offset (`waiter`, the spin loop's function), which a spin probe finds (on a host where they
# are off, the message says so instead). Leaves no process behind.
# Under [sched] preempt = "traps": these are its mechanisms (load-time points, the default,
# switch inside these loops at their points, so nothing stalls there).
#@ tier=quick
. "$(dirname "$0")/lib.inc"
out=$RUNS/09-stall
ms=$(python3 -I "$(dirname "$0")/../cpu-ms.py" timeout 120 env PATINA_TEST_STALL_MS=500 "$PATINA" run --seed 1 --config "$("$PATINA_CFG" preempt=traps)" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- /guest/spinpoints count)
[ "$(field "$out/result.json" outcome)/$(field "$out/result.json" stop)" = unsupported/compute-stall ] || die "outcome $(field "$out/result.json" outcome) $(field "$out/result.json" stop)"
case $(field "$out/result.json" message) in
*"in waiter (/guest/spinpoints+0x"* | *"Spin probes are off"* | *"A spin probe could not run"*) ;;
*) die "the message does not name the spinner's function: $(field "$out/result.json" message)" ;;
esac
[ "$ms" -ge 500 ] && [ "$ms" -le 3000 ] || die "used $ms ms of CPU time"
# No process of this run is left (launcher, sandbox keeper, supervisor or guest; see tests/leftovers.py).
rc=0; left=$(python3 -I "$(dirname "$0")/../leftovers.py" "$out") || rc=$?
[ -z "$left" ] || die "processes left: $left"
[ "$rc" = 0 ] || die "leftovers.py failed (exit $rc)"
echo "compute-stall after $ms ms of CPU time, no process left"
