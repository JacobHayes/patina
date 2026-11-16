# 8. Rust: std mpsc + UnixStream (pair, listener, datagrams); readiness through the mio
#    crate directly (Poll, Waker, UnixStream pairs). ok, identical.
#@ tier=area budget=60
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-rust; mkdir -p "$o"
for g in rs-io rs-mio; do
    for seed in 1; do
        verify_ok "$o/$g-$seed" "$seed" 3 -- /guest/$g
    done
    echo "$g: $(tail -1 "$o/$g-1/run-0/inc-0/stdout")"
done
grep -qx 'stream sent 2000 lines 2000 sum 3000499000' "$o/rs-io-1/run-0/inc-0/stdout" || die "rs-io stream totals"
grep -qx 'listener served 828000 echoed 828000' "$o/rs-io-1/run-0/inc-0/stdout" || die "rs-io listener totals"
grep -qx 'rs-mio ok bytes 2320 wakes>0 true' "$o/rs-mio-1/run-0/inc-0/stdout" || die "rs-mio totals"
io_line rust $(ls "$o"/*/run-0/outcome.json)
