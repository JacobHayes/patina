# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
GUESTS="hello-static hello-spie hello-dyn hello-rs"

# field FILE KEY[.SUB]: one (possibly nested) field of a result.json
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }

die() { echo "FAIL: $*"; exit 1; }

patina_run() { # out seed guest args...
    out=$1; seed=$2; g=$3; shift 3
    timeout 120 "$PATINA" run --seed "$seed" --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "/guest/$g" "$@" || [ -f "$out/result.json" ] || die "patina run $g: no result.json"
}
