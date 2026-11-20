# Shared helpers for the scripts of this area (sourced). Environment from ./check:
# PATINA, PATINA_RT, RUNS, PATINA_WORKLOADS. The storage reproductions workloads have their own guest directories.
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
        || [ -f "$out/result.json" ] || die "patina run $* (seed $seed): exit $? ($(tail -2 "$out.err"))"
    rm -f "$out.err"
}
# sweep NAME WORKLOAD SEEDS -- options -- cmd: tests/storage/lib/sweep.sh into $RUNS/NAME.
sweep() {
    name=$1; shift
    SWEEP_OUT=$RUNS/$name "$HERE/lib/sweep.sh" "$@" | tee "$RUNS/$name.table"
    SWEPT="${SWEPT:-} $name"
}
# matches NAME REGEX WORKLOAD SEEDS... -- options -- cmd: sweep the seeds into $RUNS/NAME and
# print, in seed order, those whose message matches REGEX. Runs that are not ok are kept as
# $RUNS/NAME/run-SEED. A finding's seeds move with the schedule (CPU count, guest build), so
# a reproduction searches a small range for the finding's signature instead of naming a seed.
matches() {
    name=$1 re=$2; shift 2
    SWEEP_OUT=$RUNS/$name "$HERE/lib/sweep.sh" "$@" >"$RUNS/$name.table"
    awk -F'\t' -v re="$re" 'NR>1 && $3 ~ re {print $1}' "$RUNS/$name/summary.tsv" | sort -n
}
# caught NAME REGEX WORKLOAD [patina options] -- cmd: a planted bug caught (a run failing with
# REGEX) in seeds 1-12, or else in seeds 13-64; fails the script if neither caught it. A
# search for the first finding, not a rate: how many seeds catch it moves with the build and
# the host.
caught() {
    _n=$1 _re=$2 _w=$3; shift 3
    sweep "$_n" "$_w" 1-12 -- "$@" >/dev/null
    [ "$(count "$_n" failure "$_re")" = 0 ] || return 0
    sweep "$_n-more" "$_w" 13-64 -- "$@" >/dev/null
    _c=$(count "$_n-more" failure "$_re")
    [ "$_c" -ge 1 ] || die "$_n: $_re not caught in seeds 1-64"
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
    # Its exit status is not the verdict (it fails on the finding the callers look for): its stderr is.
    FJ_ROOT=$copy/tree/fjtest timeout 120 "$W/fjall-harness/$bin" >/dev/null 2>"$copy/stderr" || :
    grep -v '^PROGRESS' "$copy/stderr" || [ $? = 1 ]
}
