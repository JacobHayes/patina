# 4. 1 MiB with net-delay-ms=1000..2000 takes more than 1 virtual second and under 500 ms wall.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-delay; mkdir -p "$o"
best=999999
for i in 1 2 3; do
    run_ok "$o/x$i" "$i" --fault net-delay-ms=1000..2000 -- /guest/sockets xfer 1024 1000
    w=$(field "$o/x$i/outcome.json" wall_ms)
    echo "seed $i: $(grep transfer: "$o/x$i/inc-0/stdout"); run wall $w ms"
    [ "$w" -lt "$best" ] && best=$w
done
# Load from other builders can slow a single run; the best of three must be under 500 ms.
[ "$best" -lt 500 ] || die "best wall $best ms"
run_fails "$o/x-off" 1 -- /guest/sockets xfer 1024 1000
echo "without the delay the transfer takes under 1 virtual second (the check fails as it should)"
