# 2. The guest's alternate stack: SA_ONSTACK handler on it with SS_ONSTACK, without
# SA_ONSTACK on the thread's stack, the query returns what was set; main thread and a thread.
#@ tier=quick arch=x86_64
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/02-altstack" 1 sig-alt
check_ok "$RUNS/02-altstack" sig-alt
cat "$RUNS/02-altstack/inc-0/stdout"
