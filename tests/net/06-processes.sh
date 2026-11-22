# 6. Across processes: a forking server; a socket inherited across execve; a socket whose last
#    reference is closed by exit (EOF only after the exit).
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-processes; mkdir -p "$o"
for m in forkserver execinherit; do
    verify_ok "$o/$m" 1 3 -- /guest/sockets "$m"
    sed 's/^/    /' "$o/$m/run-0/boot-1/stdout"
done
# The child sleeps 1000 ms and exits: EOF comes at >= 1000 ms.
verify_ok "$o/exitclose" 1 3 -- /guest/sockets exitclose 1000
grep -h EOF "$o/exitclose/run-0/boot-1/stdout"
