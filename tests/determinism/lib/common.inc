# Common setup of the scripts of this area (sourced). ./check provides the attack guests
# (PATINA_ATTACK_GUESTS, built once per source change by tests/guests.sh) and the workloads.
: "${PATINA:?}" "${RUNS:?}" "${PATINA_ATTACK_GUESTS:?}" "${PATINA_WORKLOADS:?}" "${PATINA_GUESTS:?}"
determinism=$(cd "$(dirname "$0")" && pwd)
export PATINA_ATTACK_WORKLOADS=$PATINA_WORKLOADS
. "$determinism/lib/workloads.inc"
die() { echo "FAIL: $*"; exit 1; }
digest() { sed -n 's/.*"digest":"\([0-9a-f]*\)".*/\1/p' "$1/outcome.json"; }
class() { sed -n 's/.*"class":"\([a-z]*\)".*/\1/p' "$1/outcome.json"; }
