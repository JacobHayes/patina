# Common setup of the sandbox hardening scripts (sourced): the determinism hardening attack guests and the sandbox hardening guests come from
# the check's guest set (tests/guests.sh: PATINA_ATTACK_GUESTS, PATINA_SANDBOX_GUESTS).
: "${PATINA:?}" "${RUNS:?}" "${PATINA_ATTACK_GUESTS:?}" "${PATINA_SANDBOX_GUESTS:?}"
sandbox=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$sandbox/../.." && pwd)
G12=$PATINA_ATTACK_GUESTS
G17=$PATINA_SANDBOX_GUESTS
die() { echo "FAIL: $*"; exit 1; }
digest() { sed -n 's/.*"digest":"\([0-9a-f]*\)".*/\1/p' "$1/outcome.json"; }
class() { sed -n 's/.*"class":"\([a-z]*\)".*/\1/p' "$1/outcome.json"; }
detail() { sed -n 's/.*"detail":"\([^"]*\)".*/\1/p' "$1/outcome.json"; }
# vfy NAME RUNS VARY GUESTDIR -- guest...: identical runs, else fail with the difference.
vfy() {
    n=$1; r=$2; v=$3; g=$4; shift 5
    rm -rf "${out:?}/$n"
    PATINA_PARALLEL=${PATINA_PARALLEL:-4} timeout 1800 "$PATINA" verify --seed 1 --runs "$r" --vary "$v" --out "$out/$n" \
        --guest "$g" -- "$@" >"$out/$n.txt" 2>&1 || die "$n: $(tail -3 "$out/$n.txt")"
    echo "$n: $r runs identical under $v ($(digest "$out/$n/run-0"))"
}
