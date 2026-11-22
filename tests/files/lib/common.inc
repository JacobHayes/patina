# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
LIB=$(cd "$(dirname "$0")/lib" && pwd)
# No guest output may grow without bound (a guest reading /dev/zero to the end, say).
ulimit -f 4000000

. "$(dirname "${BASH_SOURCE[0]}")/../../json.inc"
die() { echo "FAIL: $*"; exit 1; }

# verify_ok OUT SEED VARY RUNS [run options] -- cmd...: patina verify must report identical runs, all ok.
verify_ok() {
    out=$1; seed=$2; vary=$3; runs=$4; shift 4
    v=; [ -n "$vary" ] && v="--vary $vary"
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$runs" $v --out "$out" --mount "$PATINA_GUESTS":/guest:copy "$@" >"$out.log" 2>&1 \
        || grep -q '^identical: ' "$out.log" || { tail -5 "$out.log"; die "verify $* (seed $seed): not identical"; }
    [ "$(field "$out/run-0/result.json" outcome)" = ok ] || die "$*: class $(field "$out/run-0/result.json" outcome) $(field "$out/run-0/result.json" message)"
}

# native OUT [--disk DIR] -- cmd...: the same command natively in the sandbox (native.sh).
native() { timeout 600 "$LIB/native.sh" "$@"; }

# tree DIR: the deterministic input tree (built once per check run).
tree() {
    [ -d "$1" ] || python3 -I "$LIB/mktree.py" "$1"
}
