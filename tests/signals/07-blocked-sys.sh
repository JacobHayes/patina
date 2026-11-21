# 7. A guest that blocks every signal, SIGSYS and SIGSEGV included, with full-mask
# handlers, keeps working, and its mask query reports them blocked.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/07-blocked-sys" 1 sig-mask
check_ok "$RUNS/07-blocked-sys" sig-mask
cat "$RUNS/07-blocked-sys/inc-0/stdout"
