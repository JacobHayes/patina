# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_RT, PATINA_GUESTS, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)

# field FILE KEY: one field of an outcome.json
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }

die() { echo "FAIL: $*"; exit 1; }

patina_run() { # out seed guest args...
    out=$1; seed=$2; g=$3; shift 3
    rm -rf "$out"
    timeout 300 "$PATINA" run --seed "$seed" --out "$out" --guest "$PATINA_GUESTS" -- "/guest/$g" "$@" >/dev/null
}

# check_ok OUT GUEST [CHECKER-NAME]: outcome ok and the guest's printed results right.
check_ok() {
    [ "$(field "$1/outcome.json" class)" = ok ] || die "$2 in $1: class $(field "$1/outcome.json" class) $(field "$1/outcome.json" detail)"
    python3 -I "$HERE/check_sig.py" "${3:-$2}" "$1/inc-0/stdout" || die "$2 in $1: wrong results"
}

# verify OUT SEED GUEST RUNS: patina verify exits 0 and, independently, the run directories
# hold one digest and one stdout; the first run passes check_ok.
verify() {
    out=$1; seed=$2; g=$3; n=$4
    rm -rf "$out"
    mkdir -p "$(dirname "$out")"
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$n" --vary cpu --out "$out" --guest "$PATINA_GUESTS" -- "/guest/$g" \
        >"$out.verify.txt" 2>&1 || die "$g seed $seed: verify exit $? ($(tail -3 "$out.verify.txt"))"
    d=$(for i in $(seq 0 $((n - 1))); do field "$out/run-$i/outcome.json" digest; done | sort -u | wc -l)
    [ "$d" = 1 ] || die "$g seed $seed: $d distinct digests"
    d=$(for i in $(seq 0 $((n - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$d" = 1 ] || die "$g seed $seed: $d distinct stdout files"
    check_ok "$out/run-0" "$g"
}

# deliveries RUN: "count signal" lines of the guest signal deliveries in a boundary log.
deliveries() { "$PATINA" log dump "$1/inc-0/boundary.log" | awk '$2 == "signal" {print $5}' | sort | uniq -c; }
