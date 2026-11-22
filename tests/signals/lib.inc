# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)

# field FILE KEY[.SUB]: one (possibly nested) field of a result.json
. "$(dirname "${BASH_SOURCE[0]}")/../json.inc"

die() { echo "FAIL: $*"; exit 1; }

patina_run() { # out seed guest args...
    out=$1; seed=$2; g=$3; shift 3
    rm -rf "${out:?}"
    timeout 300 "$PATINA" run --seed "$seed" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "/guest/$g" "$@" >/dev/null || [ -f "$out/result.json" ] || die "patina run $g: no result.json"
}

# check_ok OUT GUEST [CHECKER-NAME]: outcome ok and the guest's printed results right.
check_ok() {
    [ "$(field "$1/result.json" outcome)" = ok ] || die "$2 in $1: class $(field "$1/result.json" outcome) $(field "$1/result.json" message)"
    python3 -I "$HERE/check_sig.py" "${3:-$2}" "$1/boot-1/stdout" || die "$2 in $1: wrong results"
}

# verify OUT SEED GUEST RUNS: patina verify exits 0 and, independently, the run directories
# hold one digest and one stdout; the first run passes check_ok.
verify() {
    out=$1; seed=$2; g=$3; n=$4
    rm -rf "${out:?}"
    mkdir -p "$(dirname "$out")"
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$n" --vary cpu --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "/guest/$g" \
        >"$out.verify.txt" 2>&1 || grep -q '^identical: ' "$out.verify.txt" || die "$g seed $seed: verify exit $? ($(tail -3 "$out.verify.txt"))"
    d=$(for i in $(seq 0 $((n - 1))); do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    [ "$d" = 1 ] || die "$g seed $seed: $d distinct digests"
    d=$(for i in $(seq 0 $((n - 1))); do sha256sum <"$out/run-$i/boot-1/stdout"; done | sort -u | wc -l)
    [ "$d" = 1 ] || die "$g seed $seed: $d distinct stdout files"
    check_ok "$out/run-0" "$g"
}

# deliveries RUN: "count signal" lines of the guest signal deliveries in a boundary log.
deliveries() { "$PATINA" log dump "$1/boot-1/boundary.log" | awk '$2 == "signal" {print $5}' | sort | uniq -c; }
