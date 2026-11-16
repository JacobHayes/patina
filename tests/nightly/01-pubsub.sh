# testbeds/pubsub/sim.sh at 200 seeds: each planted bug is found, the clean program is ok and
# not vacuous (see the script).
#@ tier=nightly budget=300 slots=8
set -eu
: "${PATINA:?}" "${RUNS:?}"
export CARGO_TARGET_DIR="$PATINA_CHECK_DIR/build/testbeds"
OUT="$RUNS" JOBS="${CHECK_SLOTS:-8}" exec sh testbeds/pubsub/sim.sh
