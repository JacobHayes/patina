# Shared shell setup for the counter preemption scripts (sourced). Environment from ./check.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
export PYTHONPATH="$HERE/lib"
ulimit -f 8000000
die() { echo "FAIL: $*"; exit 1; }
