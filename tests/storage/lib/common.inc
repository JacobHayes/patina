# Shared helpers for the scripts of this area (sourced). Environment from ./check:
# PATINA, PATINA_RT, RUNS, PATINA_WORKLOADS. The storage reproductions workloads have their own guest directories.
set -eu
: "${PATINA:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=${PATINA_WORKLOADS:?}
export PATINA_WORKLOADS=$W
export SWEEP_JOBS=${SWEEP_JOBS:-4}
ulimit -f 8000000
field() { jq -r ".$2" "$1"; }
die() { echo "FAIL: $*"; exit 1; }
# run WORKLOAD OUT SEED [patina options] -- /guest/cmd args: one run (OUT must not exist).
run() {
    wl=$1; out=$2; seed=$3; shift 3
    mkdir -p "$(dirname "$out")"
    timeout 600 "$PATINA" run --seed "$seed" --out "$out" --mount "$W/$wl":/guest:copy "$@" >/dev/null 2>"$out.err" \
        || [ -f "$out/outcome.json" ] || die "patina run $* (seed $seed): exit $? ($(tail -2 "$out.err"))"
    rm -f "$out.err"
}
# sweep NAME WORKLOAD SEEDS -- options -- cmd: tests/storage/lib/sweep.sh into $RUNS/NAME.
sweep() {
    name=$1; shift
    SWEEP_OUT=$RUNS/$name "$HERE/lib/sweep.sh" "$@" | tee "$RUNS/$name.table"
    SWEPT="${SWEPT:-} $name"
}
# tables: the last line of each sweep this script ran.
tables() {
    for n in ${SWEPT:-}; do echo "$n: $(tail -1 "$RUNS/$n.table")"; done
}
# count NAME CLASS [DETAIL-REGEX]: runs of the sweep with that class (and detail).
count() {
    awk -F'\t' -v c="$2" -v d="${3:-}" 'NR>1 && $2==c && (d=="" || $3 ~ d)' "$RUNS/$1/summary.tsv" | wc -l
}
# Native harness (outside patina) on a copy of a kept post-crash tree; prints its stderr.
native_fjall() {
    bin=$1; tree=$2; copy=$3
    mkdir -p "$copy"
    cp -a "$tree" "$copy/tree"
    FJ_ROOT=$copy/tree/fjtest timeout 120 "$W/fjall-harness/$bin" 2>&1 >/dev/null | grep -v '^PROGRESS' || true
}
