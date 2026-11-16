# Common setup of the sandbox hardening scripts (sourced): the determinism hardening attack guests and the sandbox hardening guests come from
# the check's guest set (tests/guests.sh: PATINA_ATTACK_GUESTS, PATINA_SANDBOX_GUESTS).
: "${PATINA:?}" "${RUNS:?}" "${PATINA_ATTACK_GUESTS:?}" "${PATINA_SANDBOX_GUESTS:?}"
sandbox=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$sandbox/../.." && pwd)
G12=$PATINA_ATTACK_GUESTS
G17=$PATINA_SANDBOX_GUESTS
die() { echo "FAIL: $*"; exit 1; }
digest() { jq -r .digest "$1/result.json"; }
class() { jq -r .outcome "$1/result.json"; }
detail() { jq -r .message "$1/result.json"; }
# vfy NAME RUNS VARY GUESTDIR -- guest...: identical runs, else fail with the difference.
vfy() {
    n=$1; r=$2; v=$3; g=$4; shift 5
    rm -rf "${out:?}/$n"
    PATINA_PARALLEL=${PATINA_PARALLEL:-4} timeout 1800 "$PATINA" verify --seed 1 --runs "$r" --vary "$v" --out "$out/$n" \
        --mount "$g":/guest:copy -- "$@" >"$out/$n.txt" 2>&1 || grep -q '^identical: ' "$out/$n.txt" || die "$n: $(tail -3 "$out/$n.txt")"
    echo "$n: $r runs identical under $v ($(digest "$out/$n/run-0"))"
}
