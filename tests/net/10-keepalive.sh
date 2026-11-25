# 10. TCP keepalive (ARCHITECTURE.md, "The fault plan"). Natively and under Patina the
# same: the options read back as set (defaults 7200/75/9, the kernel's ranges, an accepted
# socket inherits the listener's), a peer that answers its probes or has closed leaves the
# connection quiet past the budget. Under `net-blackout` (a cut on loopback) longer than the
# budget (idle 2 s, interval 1 s, 3 probes) both sides' reads fail ETIMEDOUT at it; without
# the fault the same program blocks for ever; a shorter window is survived; a side that gave
# up resets its peer's later probe; the first unanswered probe falls where Linux's would.
# Expected on the arm64 runner: about 5 s (the native runs sleep 3 s, side by side).
#@ tier=quick budget=30 slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-keepalive; rm -rf "${o:?}"; mkdir -p "$o"
for k in opts alive closed; do
    "$PATINA_GUESTS/sockets" keepalive $k >"$o/native-$k.txt" &
done
wait
for k in opts alive closed; do
    run_ok "$o/$k" 1 -- /guest/sockets keepalive $k
    diff "$o/native-$k.txt" "$o/$k/boot-1/stdout" >"$o/$k.diff" || die "$k: Patina differs from Linux: $(cat "$o/$k.diff")"
    echo "$k: as natively"
done
run_ok "$o/cut" 1 --fault net-blackout=1000+10000 -- /guest/sockets keepalive cut
sed 's/^/    /' "$o/cut/boot-1/stdout"
n=$("$PATINA" inspect events "$o/cut" | grep -c '"event":"probe"')
[ "$n" = 6 ] || die "unanswered probes in the window: $n, two sides of 3 each"
c=$(run "$o/cut-off" 1 -- /guest/sockets keepalive cut)
[ "$c" = liveness ] || die "without the blackout: class $c"
run_ok "$o/survive" 1 --fault net-blackout=1000+2500 -- /guest/sockets keepalive survive
# The side that gave up inside the window answers the other's later probe with a RST; the
# probes a reachable peer answered keep their cadence (every max(interval, idle)).
run_ok "$o/peer-rst" 1 --fault net-blackout=1000+10000 -- /guest/sockets keepalive peer-rst
run_ok "$o/cadence" 1 --fault net-blackout=25000+40000 -- /guest/sockets keepalive cadence
sed 's/^/    /' "$o/peer-rst/boot-1/stdout" "$o/cadence/boot-1/stdout"
echo "a blackout longer than the budget: both sides ETIMEDOUT; without it: $c; a shorter one survived"
