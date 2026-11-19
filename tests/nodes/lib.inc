# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_RT, PATINA_GUESTS, RUNS.
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

# The three-node store (tests/guests/nodes/q3.py) under the seed's partitions and the net preset.
Q3_FAULTS="--faults net --fault partition-gap-ms=1000..6000 --fault partition-ms=1000..6000"
Q3_SECONDS=60
# q3_sweep DIR VARIANT KEEP: seeds 1-8 of VARIANT (ok, or a planted bug) in DIR/VARIANT, the
# driver running Q3_SECONDS of virtual time; prints the report's outcomes.
q3_sweep() {
    _f=$1/$2.toml; rm -f "$_f"
    _b=""; [ "$2" = ok ] || _b=$2
    for _n in n1 n2 n3; do conf "$_f" "$_n" python3 /guest/q3.py "$_n" $_b; done
    rm -rf "${1:?}/$2"
    _st=0
    timeout 600 "$PATINA" sweep --seeds 1..8 -j 4 --keep "$3" --out "$1/$2" --config "$_f" $Q3_FAULTS \
        --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/q3.py driver "$Q3_SECONDS" >"$1/$2.txt" 2>&1 || _st=$?
    [ -f "$1/$2/report.json" ] || { tail -20 "$1/$2.txt"; die "sweep $2: no report (exit $_st)"; }
    field "$1/$2/report.json" outcomes
}
# q3_bug DIR VARIANT: the planted bug is found in most of seeds 1-8 and its first failing run
# replays identically (the sweep's own replay).
q3_bug() {
    _out=$(q3_sweep "$1" "$2" fail)
    _n=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcomes"].get("failure", 0))' "$1/$2/report.json")
    [ "$_n" -ge 4 ] || die "$2: found in only $_n of 8 seeds ($_out)"
    # Each failing group's first run, replayed by the sweep.
    _r=$(python3 -I -c 'import json,sys
g=[g for g in json.load(open(sys.argv[1]))["groups"] if g["outcome"] == "failure"]
r=["seed %s %s" % (x["replay"]["seed"], x["replay"]["result"]) for x in g if x["replay"]]
print(", ".join(r))
sys.exit(0 if r and len(r) == len(g) and all(x["replay"]["result"] == "identical" for x in g) else 1)' "$1/$2/report.json") \
        || die "$2: a first failing run did not replay identically: ${_r:-no replay}"
    _l=$(cat "$1/$2"/seed-*/inc-0/stdout 2>/dev/null | sed -n 's/^FAIL: \([a-z ]*\):.*/\1/p' | sort | uniq -c | tr -s ' \n' ' ')
    echo "$2: found in $_n of 8 seeds:$_l; replayed: $_r"
}
