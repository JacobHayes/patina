# 8. A real SIGUSR1 sent from outside to the guest's host PID: outcome internal naming the
# signal, and the guest's SIGUSR1 handler did not run.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-outside
rm -rf "$o"
timeout 300 "$PATINA" run --seed 1 --out "$o" --mount "$PATINA_GUESTS":/guest:copy -- /guest/sig-long >/dev/null &
launcher=$!
pid=
for i in $(seq 300); do
    for p in $(pgrep -u "$(id -u)" -x sig-long || true); do
        # Ours: a descendant of this launcher.
        q=$p
        while [ "$q" -gt 1 ]; do
            [ "$q" = "$launcher" ] && { pid=$p; break 3; }
            q=$(awk '/^PPid:/ {print $2}' "/proc/$q/status" 2>/dev/null || echo 1)
        done
    done
    sleep 0.1
done
[ -n "$pid" ] || { kill "$launcher"; die "guest process not found"; }
# The signal must arrive after the guest installed its handler: once its loop of getppid calls
# shows in the boundary log (its stdout reaches the run directory only at the end).
for i in $(seq 300); do
    "$PATINA" log dump "$o/inc-0/boundary.log" >"$o.dump" 2>/dev/null || true
    grep -q ' getppid ' "$o.dump" && break
    sleep 0.05
done
echo "guest host pid $pid ($(grep NSpid "/proc/$pid/status"))"
kill -USR1 "$pid"
wait "$launcher" || true
c=$(field "$o/result.json" outcome); d=$(field "$o/result.json" message)
echo "outcome: $c: $d"
[ "$c" = internal ] || die "outcome $c"
case "$d" in *SIGUSR1*) ;; *) die "detail does not name SIGUSR1: $d" ;; esac
grep -q started "$o/inc-0/stdout" || die "guest did not start"
! grep -q 'handler ran' "$o/inc-0/stdout" || die "the guest handler ran"
echo "guest handler did not run"
