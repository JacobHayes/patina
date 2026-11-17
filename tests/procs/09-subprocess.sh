# 9. subprocess from CPython: Popen with pipes, communicate, check_output of a shell pipeline,
# run, check_call failing, a missing program. ok, identical, same output as native.
#@ tier=area budget=60 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-subprocess
mkdir -p "$o"
for seed in 1; do
    verify_ok "$o/v$seed" "$seed" 3 cpu,load /usr/bin/python3 /guest/exec-files/subproc.py
done
native "$o/native.txt" /usr/bin/python3 /guest/exec-files/subproc.py || die "native: exit $?"
cmp "$o/native.txt" "$o/v1/run-0/inc-0/stdout" || { diff "$o/native.txt" "$o/v1/run-0/inc-0/stdout"; die "differs from native"; }
[ "$(tail -1 "$o/v1/run-0/inc-0/stdout")" = ok ] || die "script did not finish"
echo "equal to native; subproc $(counts "$o/v1/run-0")"
