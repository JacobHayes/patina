# 4. siglongjmp out of a handler; swapcontext and setcontext round trips.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/04-context" 1 sig-ctx
check_ok "$RUNS/04-context" sig-ctx
cat "$RUNS/04-context/inc-0/stdout"
