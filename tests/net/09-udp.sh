# 9. UDP. Socket semantics and a socket shared across fork; a request/response pair that
#    retries is ok with faults off and with datagrams dropped, and its variant without a retry
#    deadlocks within a few seeds of drops and replays identically; a reader that trusts
#    datagram order fails within a few seeds of the default delivery jitter; stock Go, Python
#    (socket and asyncio) and tokio are identical under verify; name lookups in C, Go and
#    Python answer from /etc/hosts and send no datagram.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-udp; mkdir -p "$o"
for m in semantics fork; do
    run_ok "$o/$m" 1 -- /guest/udp "$m"
    echo "$m: $(head -1 "$o/$m/inc-0/stdout")"
done
run_ok "$o/rpc" 1 -- /guest/udp rpc retry
run_ok "$o/rpc-drop" 1 --fault net-drop-permille=200 -- /guest/udp rpc retry
d=$(field "$o/rpc-drop/result.json" faults.counts.net-drop.injected)
[ "$d" -ge 1 ] || die "no datagram dropped"
echo "rpc with drops: $(head -1 "$o/rpc-drop/inc-0/stdout"), $d dropped of $(field "$o/rpc-drop/result.json" faults.counts.net-drop.eligible)"

# hunt NAME FAULT-OPTS -- ARGS: the first seed of 1..8 whose run is not ok; it replays identically.
hunt() {
    n=$1; shift
    for s in 1 2 3 4 5 6 7 8; do
        c=$(run "$o/$n-$s" "$s" "$@")
        if [ "$c" != ok ]; then
            timeout 120 "$PATINA" replay "$o/$n-$s" >"$o/$n.replay.txt" 2>&1 || true
            [ "$(field "$o/$n-$s/replay/result.json" digest)" = "$(field "$o/$n-$s/result.json" digest)" ] ||
                die "$n seed $s: replay differs ($(tail -2 "$o/$n.replay.txt"))"
            echo "$n: seed $s: $c, replayed identically; $(field "$o/$n-$s/result.json" faults.recent | python3 -I -c 'import json,sys; r=json.load(sys.stdin); print(r[-1] if r else "no fault")')"
            return 0
        fi
        rm -rf "$o/$n-$s"
    done
    die "$n: no finding in seeds 1..8"
}
hunt noretry --fault net-drop-permille=50 -- /guest/udp rpc noretry
hunt trust -- /guest/udp order trust 20
run_ok "$o/seq" 1 -- /guest/udp order seq 20

VARY=cpu,aslr
verify_ok "$o/go" 1 3 -- /guest/go-udp
verify_ok "$o/tokio" 1 3 -- /guest/tokio-udp
verify_ok "$o/py" 1 3 -- /usr/bin/python3 /guest/udp.py
for g in go tokio py; do echo "$g: $(head -1 "$o/$g/run-0/inc-0/stdout")"; done

# Names: localhost from /etc/hosts, an unknown name not found; no datagram is sent.
verify_ok "$o/dns-c" 1 2 -- /guest/udp dns
verify_ok "$o/dns-go" 1 2 -- /guest/go-udp dns
verify_ok "$o/dns-py" 1 2 -- /usr/bin/python3 /guest/udp.py dns
for g in c go py; do
    f=$o/dns-$g/run-0
    sed 's/^/    /' "$f/inc-0/stdout"
    [ "$(net "$f" datagrams)" = 0 ] || die "dns-$g sent datagrams"
    grep -q '^localhost.*127\.0\.0\.1' "$f/inc-0/stdout" || die "dns-$g: localhost"
done
grep -q '^unknown.example: error -2 ' "$o/dns-c/run-0/inc-0/stdout" || die "dns-c: EAI_NONAME"
grep -q '^unknown.example: \[\] not-found true' "$o/dns-go/run-0/inc-0/stdout" || die "dns-go: not found"
grep -q '^unknown.example gaierror -2 ' "$o/dns-py/run-0/inc-0/stdout" || die "dns-py: EAI_NONAME"
