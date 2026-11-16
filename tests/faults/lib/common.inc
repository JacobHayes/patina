# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_RT, PATINA_GUESTS, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
LIB=$HERE/lib
# Every guest and every launcher write is size-capped (a runaway file stops at 2 GB). Soft limit
# only, so that the scripts 12-earlier runs can set their own (blocking I/O raises it to 8000000).
ulimit -S -f 4000000

field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }
die() { echo "FAIL: $*"; exit 1; }

# run OUT SEED [patina run options] -- /guest/cmd args: one run (OUT replaced).
run() {
    out=$1; seed=$2; shift 2
    rm -rf "$out"
    mkdir -p "$(dirname "$out")"
    timeout 600 "$PATINA" run --seed "$seed" --out "$out" --guest "$PATINA_GUESTS" "$@" >/dev/null 2>"$out.err" \
        || die "patina run $* (seed $seed): exit $? ($(tail -2 "$out.err"))"
    rm -f "$out.err"
}

# verify OUT SEED RUNS VARY [patina options] -- cmd: patina verify identical.
verify() {
    out=$1; seed=$2; n=$3; vary=$4; shift 4
    rm -rf "$out"
    mkdir -p "$(dirname "$out")"
    v=; [ -n "$vary" ] && v="--vary $vary"
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$n" $v --out "$out" --guest "$PATINA_GUESTS" "$@" >"$out.log" 2>&1 \
        || die "verify $* (seed $seed): not identical ($(tail -3 "$out.log"))"
}

class() { field "$1/outcome.json" class; }

# sweep NAME SEEDS [patina run options] -- /guest/cmd args: one run per seed (1..SEEDS),
# $T07_JOBS (default 4) at a time, through tests/storage/lib/sweep.sh: $RUNS/NAME/summary.tsv
# (seed class detail digest incarnations crashes wall_ms); run directories deleted unless
# SWEEP_KEEP says otherwise (all, fail).
sweep() {
    _n=$1; _s=$2; shift 2
    SWEEP_OUT=$RUNS/$_n SWEEP_KEEP=${SWEEP_KEEP:-none} SWEEP_JOBS=${T07_JOBS:-4} PATINA_WORKLOADS=$(dirname "$PATINA_GUESTS") \
        "$HERE/../storage/lib/sweep.sh" "$(basename "$PATINA_GUESTS")" "1-$_s" -- "$@" >"$RUNS/$_n.table"
}
