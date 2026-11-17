# 6. Across processes: a forking server; a socket inherited across execve; a socket whose last
#    reference is closed by exit (EOF only after the exit and the FIN delay).
#@ tier=quick budget=30 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-processes; mkdir -p "$o"
for m in forkserver execinherit; do
    verify_ok "$o/$m" 1 3 -- /guest/sockets "$m"
    sed 's/^/    /' "$o/$m/run-0/inc-0/stdout"
done
# The child sleeps 1000 ms and exits; the FIN takes 300 ms more: EOF at >= 1300 ms.
verify_ok "$o/exitclose" 1 3 --fault net-halfclose-delay-ms=300..300 -- /guest/sockets exitclose 1300
grep -h EOF "$o/exitclose/run-0/inc-0/stdout"
run_fails "$o/exitclose-off" 1 -- /guest/sockets exitclose 1300
echo "without the FIN delay EOF comes at the exit (the 1300 ms check fails as it should)"
