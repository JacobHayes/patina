# 6. Cross-process signals: kill between siblings, kill to a process group, SIGTERM (default
# action) killing a child blocked in read; the wait status shows the signal. Same as native.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-signals
mkdir -p "$o"
verify_ok "$o/v" 1 3 cpu,load /guest/xsig
native "$o/native.txt" /guest/xsig || die "native: exit $?"
cmp "$o/native.txt" "$o/v/run-0/inc-0/stdout" || { diff "$o/native.txt" "$o/v/run-0/inc-0/stdout"; die "differs from native"; }
python3 -I "$HERE/check_procs.py" xsig "$o/v/run-0/inc-0/stdout" || die "wrong values"
cat "$o/v/run-0/inc-0/stdout"
