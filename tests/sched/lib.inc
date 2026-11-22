# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
GUESTS="c-threads rs-threads order"
HERE=$(cd "$(dirname "$0")" && pwd)

# field FILE KEY[.SUB]: one (possibly nested) field of a result.json
. "$(dirname "${BASH_SOURCE[0]}")/../json.inc"

die() { echo "FAIL: $*"; exit 1; }

patina_run() { # out seed guest args...   (extra patina options in $PATINA_OPTS)
    out=$1; seed=$2; g=$3; shift 3
    timeout 120 "$PATINA" run ${PATINA_OPTS:-} --seed "$seed" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "/guest/$g" "$@" >/dev/null || [ -f "$out/result.json" ] || die "patina run $g: no result.json"
}

# check_result OUT GUEST: outcome ok and the guest's own results correct.
check_result() {
    [ "$(field "$1/result.json" outcome)" = ok ] || die "$2 in $1: class $(field "$1/result.json" outcome) $(field "$1/result.json" message)"
    python3 -I "$HERE/check_threads.py" "$2" "$1/boot-1/stdout" || die "$2 in $1: wrong results"
}
