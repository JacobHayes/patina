# 2. Socket semantics: each mode checks what it observes and exits non-zero otherwise.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-semantics; mkdir -p "$o"
for m in names refused addrinuse halfclose eof rst epipe sigpipe-kill rcvtimeo peek waitall sendfile v6; do
    run_ok "$o/$m" 1 -- /guest/sockets "$m"
    echo "$m: ok"
done
# 64 MiB through a slow reader: back-pressure keeps the supervisor's queue at one window.
run_ok "$o/big" 1 -- /guest/sockets big 64
q=$(net "$o/big" peak_queued); h=$(net "$o/big" sup_hwm_kb); b=$(net "$o/big" bytes)
log=$(stat -c %s "$o/big/inc-0/boundary.log")
echo "big 64 MiB: bytes $b, peak queued $q bytes, supervisor VmHWM $h KiB (boundary log $log bytes, mapped), steps $(net "$o/big" steps)"
[ "$b" -ge 67108864 ] || die "bytes $b"
[ "$q" -le 1048576 ] || die "the supervisor queued $q bytes"
rm -f "$o/big/inc-0/boundary.log"
