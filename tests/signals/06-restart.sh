# 6. Restart: in one thread signalled by its own timer, a futex wait and a pipe read restarted
# under SA_RESTART with their own arguments, and EINTR without it; nanosleep (EINTR, remaining
# time in virtual time), futex wait with and without SA_RESTART and with a timeout, from a
# second thread. Pipe read and poll need blocking I/O's blocking I/O (before it, a read on an
# empty pipe blocks in the kernel): that part runs, and must pass, once tests/io exists.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/06-restart/self" 1 sig-restart self
check_ok "$RUNS/06-restart/self" sig-restart sig-restart-self
cat "$RUNS/06-restart/self/boot-1/stdout"
patina_run "$RUNS/06-restart/wait" 1 sig-restart
check_ok "$RUNS/06-restart/wait" sig-restart
cat "$RUNS/06-restart/wait/boot-1/stdout"
if [ -d "$HERE/../io" ]; then
    patina_run "$RUNS/06-restart/io" 1 sig-restart io
    check_ok "$RUNS/06-restart/io" sig-restart sig-restart-io
    cat "$RUNS/06-restart/io/boot-1/stdout"
else
    echo "NOT RUN: pipe read and poll: blocking pipe I/O is blocking I/O (tests/io not present)"
fi
