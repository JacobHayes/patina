# Shared helpers for the compute-point scripts (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, PATINA_CFG, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
G=$PATINA_GUESTS
die() { echo "FAIL: $*"; exit 1; }
[ ! -f "$G/compute/MISSING" ] || die "$(cat "$G/compute/MISSING")"

# field FILE KEY[.SUB]: one (possibly nested) field of a result.json ("-" if absent)
. "$(dirname "${BASH_SOURCE[0]}")/../json.inc"
field() { field_opt "$@"; }

# prun OUT SEED [patina options] -- PROG ARGS...: one run with the guests at /guest
prun() {
    o=$1 s=$2; shift 2
    rm -rf "${o:?}"
    timeout 60 "$PATINA" run --seed "$s" --out "$o" --mount "$G":/guest:copy "$@" >/dev/null 2>&1 || true
    [ -f "$o/result.json" ] || die "no result.json in $o"
}
res() { echo "$(field "$1/result.json" outcome)/$(field "$1/result.json" stop): $(field "$1/result.json" message)"; }

# hunt DIR NAME MAX [patina options] -- PROG ARGS...: runs DIR/NAME-SEED of seeds 1..MAX, four
# at a time, stopping after the first four that hold a `failure`; every run must end `ok` or
# `failure`. Sets first (the lowest failing seed, empty if none), found and scanned.
hunt() {
    hd=$1 hn=$2 hmax=$3; shift 3
    first="" found=0 scanned=0
    while [ -z "$first" ] && [ "$scanned" -lt "$hmax" ]; do
        he=$((scanned + 4)); [ "$he" -le "$hmax" ] || he=$hmax
        seq $((scanned + 1)) "$he" | G=$G xargs -P 4 -I{} bash -euo pipefail -O inherit_errexit -c '
            d=$1/$2-$3; shift 3; rm -rf "${d:?}"
            timeout 60 "$PATINA" run --seed "${d##*-}" --out "$d" --mount "$G":/guest:copy "$@" >/dev/null 2>&1 || true' \
            sh "$hd" "$hn" {} "$@"
        for x in $(seq $((scanned + 1)) "$he"); do
            [ -f "$hd/$hn-$x/result.json" ] || die "$hn seed $x: no result.json"
            case $(field "$hd/$hn-$x/result.json" outcome) in
                failure) found=$((found + 1)); [ -n "$first" ] || first=$x ;;
                ok) ;;
                *) die "$hn seed $x: $(res "$hd/$hn-$x")" ;;
            esac
        done
        scanned=$he
    done
}
