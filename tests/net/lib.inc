# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_RT, PATINA_GUESTS, RUNS.
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
# No guest output or boundary log may grow without bound (dash: 512-byte blocks, 2 GB).
ulimit -S -f 4000000

field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]));
for k in sys.argv[2].split("."): v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }
die() { echo "FAIL: $*"; exit 1; }
VARY=cpu,load,sandbox

# run OUT SEED [patina options] -- /guest/prog args: one run; prints the class.
run() {
    out=$1; seed=$2; shift 2
    rm -rf "$out"
    timeout 600 "$PATINA" run --seed "$seed" --out "$out" --guest "$PATINA_GUESTS" "$@" >/dev/null 2>"$out.err" \
        || die "patina run $*: exit $?"
    field "$out/outcome.json" class
}
# run_ok OUT SEED [patina options] -- /guest/prog args: one run, outcome ok.
run_ok() {
    c=$(run "$@")
    [ "$c" = ok ] || die "$* : class $c: $(field "$1/outcome.json" detail)"
}
# run_fails OUT SEED [patina options] -- /guest/prog args: the guest fails (exit status != 0).
run_fails() {
    c=$(run "$@")
    [ "$c" = failed ] || die "$* : expected the guest to fail, class $c: $(field "$1/outcome.json" detail)"
}
net() { field "$1/outcome.json" "net.$2"; }

# verify_same OUT SEED RUNS [patina options] -- cmd: patina verify says identical; independently one
# digest and one stdout over the run directories. Prints the first run's class.
verify_same() {
    out=$1; seed=$2; runs=$3; shift 3
    rm -rf "$out"
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$runs" --vary "$VARY" --out "$out" --guest "$PATINA_GUESTS" "$@" \
        >"$out.verify.txt" 2>&1 || { tail -5 "$out.verify.txt"; die "verify $* (seed $seed): exit $?"; }
    _n=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/outcome.json" digest; done | sort -u | wc -l)
    [ "$_n" = 1 ] || die "$* seed $seed: $_n distinct digests"
    _n=$(for i in $(seq 0 $((runs - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$_n" = 1 ] || die "$* seed $seed: $_n distinct stdout files"
    echo "seed $seed: $runs identical runs, digest $(field "$out/run-0/outcome.json" digest), class $(field "$out/run-0/outcome.json" class), cpus $(grep -o 'cpu [0-9]*' "$out.verify.txt" | sort -u | wc -l)"
    # Keep the evidence small: one boundary log per verify.
    for i in $(seq 1 $((runs - 1))); do rm -f "$out/run-$i/inc-"*/boundary.log; done
}
verify_ok() {
    verify_same "$@"
    [ "$(field "$1/run-0/outcome.json" class)" = ok ] || die "$* : class $(field "$1/run-0/outcome.json" class): $(field "$1/run-0/outcome.json" detail)"
}
