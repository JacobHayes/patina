# testbeds/pubsub/sim.sh at 200 seeds: each planted bug is found, the clean program is ok and
# not vacuous (see the script).
#@ tier=release budget=120 slots=8
: "${PATINA:?}" "${RUNS:?}"
export CARGO_TARGET_DIR="$PATINA_CHECK_DIR/build/testbeds"
OUT="$RUNS" JOBS="${CHECK_SLOTS:-8}" exec bash testbeds/pubsub/sim.sh
