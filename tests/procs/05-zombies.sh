# 5. Zombies and orphans: kill(pid, 0) succeeds on a zombie and waitpid then returns it (then
# ESRCH); a grandchild whose parent died reports getppid() == 1. Same as native, identical runs.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-zombies
mkdir -p "$o"
verify_ok "$o/v" 1 3 cpu,load /guest/zombies
python3 -I "$HERE/check_procs.py" zombies "$o/v/run-0/boot-1/stdout" || die "wrong values"
native "$o/native.txt" /guest/zombies || die "native: exit $?"
python3 -I "$HERE/check_procs.py" zombies "$o/native.txt" || die "native gives other values"
cat "$o/v/run-0/boot-1/stdout"
