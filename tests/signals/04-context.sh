# 4. siglongjmp out of a handler; swapcontext and setcontext round trips; a handler that sets
# the interrupted call's return register to INT64_MIN and to -EFBIG gets them back after
# rt_sigreturn, also where the host's RLIMIT_FSIZE is finite (a call's EFBIG there ends the run
# `infra`, a restored register's never).
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/04-context" 1 sig-ctx
check_ok "$RUNS/04-context" sig-ctx
cat "$RUNS/04-context/inc-0/stdout"
(ulimit -f 1048576 && patina_run "$RUNS/04-context-fsize" 1 sig-ctx) || die "sig-ctx under ulimit -f: no run"
check_ok "$RUNS/04-context-fsize" sig-ctx
