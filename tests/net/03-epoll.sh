# 3. epoll echo server, level and edge triggered, 50 non-blocking clients x 100 messages;
#    a non-blocking connect is not writable before the handshake (500 ms delay).
#@ tier=quick budget=30 slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/03-epoll; mkdir -p "$o"
for m in lt et; do
    run_ok "$o/$m" 1 -- /guest/sockets epoll "$m" 50 100
    echo "epoll $m: $(tail -2 "$o/$m/boot-1/stdout" | head -1); wall $(field "$o/$m/result.json" wall_ms) ms, connections $(net "$o/$m" connections)"
    [ "$(net "$o/$m" connections)" -ge 50 ] || die "connections"
done
run_ok "$o/nb" 1 --fault net-delay-ms=500..500 -- /guest/sockets nbconnect 500
echo "nbconnect: $(head -1 "$o/nb/boot-1/stdout")"
# Without the delay the same check (POLLOUT only after 500 ms) fails.
run_fails "$o/nb-off" 1 -- /guest/sockets nbconnect 500
echo "nbconnect without the delay: fails as it should"
