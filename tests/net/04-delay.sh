# 4. 1 MiB with net-delay-ms=20000..30000 takes more than 30 virtual seconds, twice this
#    script's budget, so a real wait would fail it (no wall time is read).
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-delay; mkdir -p "$o"
for i in 1 2 3; do
    run_ok "$o/x$i" "$i" --fault net-delay-ms=20000..30000 -- /guest/sockets xfer 1024 30000
    echo "seed $i: $(grep transfer: "$o/x$i/inc-0/stdout"); run wall $(field "$o/x$i/result.json" wall_ms) ms"
done
run_fails "$o/x-off" 1 -- /guest/sockets xfer 1024 30000
echo "without the delay the transfer takes under 30 virtual seconds (the check fails as it should)"
