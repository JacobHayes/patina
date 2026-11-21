# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS.
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
# No guest output or boundary log may grow without bound (dash: 512-byte blocks, 2 GB).
ulimit -S -f 4000000

field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]));
for k in sys.argv[2].split("."): v=v[int(k)] if isinstance(v,list) else v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }
die() { echo "FAIL: $*"; exit 1; }
VARY=cpu,load,aslr,sandbox,repeat

# run OUT SEED [patina options] -- /guest/prog args: one run; prints the class.
run() {
    out=$1; seed=$2; shift 2
    rm -rf "${out:?}"
    timeout 600 "$PATINA" run --seed "$seed" --out "$out" --mount "$PATINA_GUESTS":/guest:copy "$@" >/dev/null 2>"$out.err" \
        || [ -f "$out/result.json" ] || die "patina run $*: no result.json"
    field "$out/result.json" outcome
}
# run_ok OUT SEED [patina options] -- /guest/prog args: one run, outcome ok.
run_ok() {
    c=$(run "$@")
    [ "$c" = ok ] || die "$* : class $c: $(field "$1/result.json" message)"
}
# run_fails OUT SEED [patina options] -- /guest/prog args: the guest fails (exit status != 0).
run_fails() {
    c=$(run "$@")
    [ "$c" = failure ] || die "$* : expected the guest to fail, class $c: $(field "$1/result.json" message)"
}
net() { field "$1/result.json" "counters.net.$2"; }

# verify_same OUT SEED RUNS [patina options] -- cmd: patina verify says identical; independently one
# digest and one stdout over the run directories. Prints the first run's class.
verify_same() {
    out=$1; seed=$2; runs=$3; shift 3
    rm -rf "${out:?}"
    timeout 1800 "$PATINA" verify --seed "$seed" --runs "$runs" --vary "$VARY" --out "$out" --mount "$PATINA_GUESTS":/guest:copy "$@" \
        >"$out.verify.txt" 2>&1 || grep -q '^identical: ' "$out.verify.txt" || { tail -5 "$out.verify.txt"; die "verify $* (seed $seed): exit $?"; }
    _n=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    [ "$_n" = 1 ] || die "$* seed $seed: $_n distinct digests"
    _n=$(for i in $(seq 0 $((runs - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$_n" = 1 ] || die "$* seed $seed: $_n distinct stdout files"
    echo "seed $seed: $runs identical runs, digest $(field "$out/run-0/result.json" digest), class $(field "$out/run-0/result.json" outcome), cpus $(grep -o 'cpu [0-9]*' "$out.verify.txt" | sort -u | wc -l)"
    # Keep the evidence small: one boundary log per verify.
    for i in $(seq 1 $((runs - 1))); do rm -f "$out/run-$i/inc-"*/boundary.log; done
}
verify_ok() {
    verify_same "$@"
    [ "$(field "$1/run-0/result.json" outcome)" = ok ] || die "$* : class $(field "$1/run-0/result.json" outcome): $(field "$1/run-0/result.json" message)"
}

# conf FILE NAME CMD...: append a node to a configuration file.
conf() {
    f=$1; n=$2; shift 2
    printf '[node.%s]\ncmd = [' "$n" >>"$f"
    sep=""
    for a in "$@"; do printf '%s"%s"' "$sep" "$a" >>"$f"; sep=", "; done
    printf ']\n' >>"$f"
}

# Finding a planted bug: a search, not a rate. How often a bug shows over a fixed range of
# seeds depends on the build, the host's interpreters and libraries, and the seeds, so a
# threshold on that count fails without any defect. A planted bug is instead searched for over
# seeds 1-FIND_SEEDS, stopping at the first finding; then facts about that run are asserted.
FIND_SEEDS=64
# find_bug DIR VARIANT [sweep options] -- CMD...: a sweep of seeds 1-FIND_SEEDS in DIR/VARIANT
# that stops launching runs at the first finding (`--max-findings 1`); asserts a failure was
# found and that every failing group's first run replayed identically (the sweep's own replay);
# prints the seeds it needed and the replays. The failing runs are kept.
find_bug() {
    _d=$1/$2; shift 2
    rm -rf "${_d:?}"
    _st=0
    timeout 900 "$PATINA" sweep --seeds 1..$FIND_SEEDS -j 4 --max-findings 1 --keep fail --out "$_d" \
        --mount "$PATINA_GUESTS":/guest:copy "$@" >"$_d.txt" 2>&1 || _st=$?
    [ -f "$_d/report.json" ] || { tail -20 "$_d.txt"; die "sweep $_d: no report (exit $_st)"; }
    python3 -I -c 'import json,sys
r=json.load(open(sys.argv[1]))
n=r["outcomes"].get("failure", 0)
runs=sum(r["outcomes"].values())
g=[g for g in r["groups"] if g["outcome"] == "failure"]
p=["seed %s %s" % (x["replay"]["seed"], x["replay"]["result"]) for x in g if x["replay"]]
if not n:
    sys.exit("FAIL: not found in seeds 1-%s: %s" % (sys.argv[2], json.dumps(r["outcomes"])))
if not p or len(p) != len(g) or any(x["replay"]["result"] != "identical" for x in g):
    sys.exit("FAIL: a first failing run did not replay identically: %s" % (", ".join(p) or "no replay"))
print("found after %d runs of seeds 1-%s; replayed: %s" % (runs, sys.argv[2], ", ".join(p)))' "$_d/report.json" "$FIND_SEEDS"
}
