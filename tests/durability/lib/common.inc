# Shared settings for the durability scripts (sourced). Environment from ./check: PATINA, RUNS,
# PATINA_WORKLOADS.
set -eu
: "${PATINA:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=${PATINA_WORKLOADS:?}
ulimit -f 8000000
die() { echo "FAIL: $*"; exit 1; }
