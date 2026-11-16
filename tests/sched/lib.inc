# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_RT, PATINA_GUESTS, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
GUESTS="c-threads rs-threads order"
HERE=$(cd "$(dirname "$0")" && pwd)

# field FILE KEY: one field of an outcome.json
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }

die() { echo "FAIL: $*"; exit 1; }

patina_run() { # out seed guest args...   (extra patina options in $PATINA_OPTS)
    out=$1; seed=$2; g=$3; shift 3
    timeout 120 "$PATINA" run ${PATINA_OPTS:-} --seed "$seed" --out "$out" --guest "$PATINA_GUESTS" -- "/guest/$g" "$@" >/dev/null
}

# check_result OUT GUEST: outcome ok and the guest's own results correct.
check_result() {
    [ "$(field "$1/outcome.json" class)" = ok ] || die "$2 in $1: class $(field "$1/outcome.json" class) $(field "$1/outcome.json" detail)"
    python3 -I "$HERE/check_threads.py" "$2" "$1/inc-0/stdout" || die "$2 in $1: wrong results"
}
