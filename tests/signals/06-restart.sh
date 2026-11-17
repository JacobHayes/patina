# 6. Restart: nanosleep (EINTR, remaining time in virtual time), futex wait with and without
# SA_RESTART and with a timeout. Pipe read and poll need blocking I/O's blocking I/O (before it, a read
# on an empty pipe blocks in the kernel): that part runs, and must pass, once tests/io exists.
#@ tier=quick arch=x86_64
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/06-restart/wait" 1 sig-restart
check_ok "$RUNS/06-restart/wait" sig-restart
cat "$RUNS/06-restart/wait/inc-0/stdout"
if [ -d "$HERE/../io" ]; then
    patina_run "$RUNS/06-restart/io" 1 sig-restart io
    check_ok "$RUNS/06-restart/io" sig-restart sig-restart-io
    cat "$RUNS/06-restart/io/inc-0/stdout"
else
    echo "NOT RUN: pipe read and poll: blocking pipe I/O is blocking I/O (tests/io not present)"
fi
