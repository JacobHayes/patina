# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
# No guest output or log may grow without bound. The ring test's boundary logs reach about
# 3 GB per run (deleted after each run); dash counts this limit in 512-byte blocks.
ulimit -f 8000000

. "$(dirname "${BASH_SOURCE[0]}")/../json.inc"
die() { echo "FAIL: $*"; exit 1; }

# run_ok OUT SEED [patina options] -- /guest/prog args: one run, outcome ok.
run_ok() {
    out=$1; seed=$2; shift 2
    timeout 600 "$PATINA" run --seed "$seed" --out "$out" --mount "$PATINA_GUESTS":/guest:copy "$@" >/dev/null 2>"$out.err" \
        || [ -f "$out/result.json" ] || die "patina run $*: no result.json"
    [ "$(field "$out/result.json" outcome)" = ok ] || die "$* (seed $seed): class $(field "$out/result.json" outcome): $(field "$out/result.json" message)"
}

# verify_ok OUT SEED RUNS [patina options] -- cmd: patina verify --vary cpu,load says identical; independently
# one digest and one stdout over the run directories; the first run is ok.
verify_ok() {
    out=$1; seed=$2; runs=$3; shift 3
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$runs" --vary cpu,load --out "$out" --mount "$PATINA_GUESTS":/guest:copy "$@" \
        >"$out.verify.txt" 2>&1 || grep -q '^identical: ' "$out.verify.txt" || { tail -5 "$out.verify.txt"; die "verify $* (seed $seed): exit $?"; }
    n=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$* seed $seed: $n distinct digests"
    n=$(for i in $(seq 0 $((runs - 1))); do sha256sum <"$out/run-$i/boot-1/stdout"; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$* seed $seed: $n distinct stdout files"
    [ "$(field "$out/run-0/result.json" outcome)" = ok ] || die "$* seed $seed: class $(field "$out/run-0/result.json" outcome)"
    echo "seed $seed: $runs identical runs, digest $(field "$out/run-0/result.json" digest), cpus $(grep -o 'cpu [0-9]*' "$out.verify.txt" | sort -u | wc -l)"
}

# io_line LABEL OUTCOME...: the blocking-I/O counters summed over outcome files, and the
# spurious re-attempt rate (re-attempts / blocking calls completed).
io_line() {
    label=$1; shift
    python3 -I - "$label" "$@" <<'PY'
import json, sys
k = ["parks", "reattempts", "spurious", "blocking_done", "blocking_parked"]
s = dict.fromkeys(k, 0)
for f in sys.argv[2:]:
    io = json.load(open(f))["counters"]["io"]
    for x in k:
        s[x] += io[x]
rate = s["reattempts"] / s["blocking_done"] if s["blocking_done"] else 0
print("IO %s runs=%d %s rate=%.3f spurious_per_call=%.3f" % (sys.argv[1], len(sys.argv) - 2,
      " ".join("%s=%d" % (x, s[x]) for x in k), rate, s["spurious"] / max(1, s["blocking_done"])))
PY
}
