#!/bin/sh
# 10. Spin-waits without a system call or `pause` (tests/guests/threads/spinpoints.c), with
# stall-ms = 1000:
#  a. A flag spin (each iteration leaves the state unchanged) is found by a spin probe and the
#     run ends ok; with probes off it ends unsupported, stop compute-stall.
#  b. A spin that counts its iterations cannot be preempted: unsupported, stop compute-stall,
#     within stall-ms plus a margin, naming the spinning thread; the same seed twice stops at
#     the same record (same digest).
#  c. One thread computing for about 2 s with no other thread is ok, not a stall.
#  d. Stock Go at the default CPU count (go-sweep, whose background sweeper spins without a
#     system call or `pause`) ends ok on seeds 1-3.
#@ tier=quick budget=30 slots=5
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-spin
mkdir -p "$o"
on=$("$PATINA_CFG" stall-ms=1000)
off=$("$PATINA_CFG" stall-ms=1000 spin-probes=false)
one() { # OUT GUESTDIR SEED CONFIG -- PROG ARGS...
    d=$o/$1 g=$2 s=$3 c=$4; shift 4
    rm -rf "$d"
    timeout 60 "$PATINA" run --seed "$s" --config "$c" --out "$d" --mount "$g":/guest:copy "$@" >/dev/null 2>&1 || true
}
G=$PATINA_GUESTS
one flag "$G" 1 "$on" -- /guest/spinpoints flag &
one flag-off "$G" 1 "$off" -- /guest/spinpoints flag &
t0=$(date +%s%N)
(one count-a "$G" 1 "$on" -- /guest/spinpoints count; echo $(( ($(date +%s%N) - t0) / 1000000 )) >"$o/count-a.ms")&
one count-b "$G" 1 "$on" -- /guest/spinpoints count &
one alone "$G" 1 "$on" -- /guest/spinpoints alone 2000 &
wait
for s in 1 2 3; do one "go-$s" "$PATINA_WORKLOADS/go-static" "$s" "$on" -- /guest/go-sweep & done
wait
res() { echo "$(field "$o/$1/result.json" outcome)/$(field "$o/$1/result.json" stop): $(field "$o/$1/result.json" message)"; }
stall() { [ "$(field "$o/$1/result.json" outcome)/$(field "$o/$1/result.json" stop)" = unsupported/compute-stall ]; }

[ "$(field "$o/flag/result.json" outcome)" = ok ] || die "a. flag spin: $(res flag)"
[ "$(field "$o/flag/result.json" counters.sched.spin_found)" -gt 0 ] || die "a. flag spin: ok without a found spin"
stall flag-off || die "a. flag spin, probes off: $(res flag-off)"
echo "a. flag spin: ok, preemptions $(field "$o/flag/result.json" sched.preemptions); probes off: $(res flag-off | cut -c1-60)"

stall count-a || die "b. counting spin: $(res count-a)"
ms=$(cat "$o/count-a.ms")
[ "$ms" -le 4000 ] || die "b. counting spin took $ms ms"
field "$o/count-a/result.json" message | grep -q spinpoints || die "b. the message does not name the thread: $(res count-a)"
[ "$(field "$o/count-a/result.json" digest)" = "$(field "$o/count-b/result.json" digest)" ] ||
    die "b. the same seed stopped at different records"
echo "b. counting spin after $ms ms: $(res count-a | cut -c1-110)"

[ "$(field "$o/alone/result.json" outcome)" = ok ] || die "c. lone compute: $(res alone)"
echo "c. lone compute of about 2 s: ok, wall $(field "$o/alone/result.json" wall_ms) ms"

for s in 1 2 3; do
    [ "$(field "$o/go-$s/result.json" outcome)" = ok ] || die "d. go-sweep seed $s: $(res "go-$s")"
done
echo "d. go-sweep at the default CPU count: ok on seeds 1-3 (spin points found on seed 1: $(field "$o/go-1/result.json" counters.sched.spin_found))"
