# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
# field FILE KEY[.SUB]: one (possibly nested) field of a JSON file
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) or v is None else v)' "$1" "$2"; }
# exit_of OUTCOME: the exit status `patina --help --format json` documents for an outcome
exit_of() { "$PATINA" --help --format json | python3 -I -c 'import json,sys
print(next(o["exit"] for o in json.load(sys.stdin)["outcomes"] if o["name"] == sys.argv[1]))' "$1"; }
# prun OUT [run options] -- CMD...: `patina run` into OUT; sets $st to its exit status.
prun() {
    out=$1; shift
    st=0
    timeout 60 "$PATINA" run --out "$out" "$@" >"$out.txt" 2>&1 || st=$?
}
