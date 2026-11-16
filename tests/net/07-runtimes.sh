# 7. Runtimes: Rust std::net, tokio multi-thread echo, Python socket+selectors, Go net
#    listener+dialer in one process. Each ok and identical across 3 runs.
#@ tier=area budget=90
. "$(dirname "$0")/lib.inc"
o=$RUNS/07-runtimes; mkdir -p "$o"
check() {
    g=$1; shift
    verify_ok "$o/$g" 1 3 -- "$@"
    echo "$g: $(tail -1 "$o/$g/run-0/inc-0/stdout"); net $(field "$o/$g/run-0/outcome.json" counters.net); refused $(field "$o/$g/run-0/outcome.json" refused)"
    [ "$(net "$o/$g/run-0" unknown_opts)" = 0 ] || die "$g set an unknown socket option"
}
check rs-net /guest/rs-net
grep -q 'served 4200 checksum 344400 v6 v6 refused ConnectionRefused' "$o/rs-net/run-0/inc-0/stdout" || die "rs-net totals"
check tokio-echo /guest/tokio-echo
grep -q 'lines 1000 checksum 1533500 idle read timed out true' "$o/tokio-echo/run-0/inc-0/stdout" || die "tokio totals"
check py-net /usr/bin/python3 /guest/py-net.py
grep -q 'served 6720 checksum 540000 timeout True refused True' "$o/py-net/run-0/inc-0/stdout" || die "python totals"
check go-net /guest/go-net
grep -q 'lines 800 checksum 1668500 deadline true redial refused true' "$o/go-net/run-0/inc-0/stdout" || die "go totals"
