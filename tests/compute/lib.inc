# Shared helpers for the compute-point scripts (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, PATINA_CFG, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
G=$PATINA_GUESTS
die() { echo "FAIL: $*"; exit 1; }
[ ! -f "$G/compute/MISSING" ] || die "$(cat "$G/compute/MISSING")"

# field FILE KEY[.SUB]: one (possibly nested) field of a result.json ("-" if absent)
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    if not isinstance(v, dict) or k not in v: print("-"); sys.exit()
    v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }

# prun OUT SEED [patina options] -- PROG ARGS...: one run with the guests at /guest
prun() {
    o=$1 s=$2; shift 2
    rm -rf "$o"
    timeout 60 "$PATINA" run --seed "$s" --out "$o" --mount "$G":/guest:copy "$@" >/dev/null 2>&1 || true
    [ -f "$o/result.json" ] || die "no result.json in $o"
}
res() { echo "$(field "$1/result.json" outcome)/$(field "$1/result.json" stop): $(field "$1/result.json" message)"; }
