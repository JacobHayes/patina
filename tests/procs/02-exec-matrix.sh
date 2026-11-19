# 2. Exec matrix: 8 targets x {fork+execve, vfork+execve, posix_spawn} and 6 failures x 3
# methods. stdout equals a native run of the same guest (the sandbox without the runtime: the
# same /guest layout and a fresh PID namespace), and the derived values are right: the image each
# child saw, its argv, its environment variable, inherited descriptors 0,1,2,5 (5 inherited, 6
# close-on-exec gone), the hidden descriptor EBADF, and the kernel's error for each failure
# (posix_spawn returns it).
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-exec-matrix
mkdir -p "$o"
verify_ok "$o/v" 1 3 cpu,load /guest/exec-matrix
native "$o/native.txt" /guest/exec-matrix || die "native run: exit $?"
cmp "$o/native.txt" "$o/v/run-0/inc-0/stdout" || { diff "$o/native.txt" "$o/v/run-0/inc-0/stdout" | head -20; die "differs from native"; }
echo "stdout equals the native run ($(wc -l <"$o/native.txt") lines)"
python3 -I "$HERE/check_procs.py" matrix "$o/v/run-0/inc-0/stdout" || die "wrong values"
echo "exec-matrix $(counts "$o/v/run-0")"
