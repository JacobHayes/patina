# 14. `patina explain` on four kinds of failure, each the first failing seed of 1-64: a race
#    between threads (the jobs example), crash consistency (acklog under `--crash machine`), a
#    two-node bug (tests/guests/nodes/kv.py, the backup acknowledging before it applies) and a
#    three-node split brain (tests/guests/nodes/q3.py nofence under partitions). Which seed fails
#    first depends on the host, so what is asserted holds for every failing seed: each story is
#    shorter than the event log (far shorter for the nodes) and stops at the event the run
#    gives: the failed assertion, the failing thread's output, the message into the driver that
#    it found wrong (from the node that sent it), with the last partition before it. Then the
#    observed replay is the run for every run of an examples sweep kept whole, a node sweep and a
#    sweep with load-time points.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib.inc"
G=$PATINA_GUESTS
# first OUT SEEDS OUTCOME [run options] -- CMD: the first seed of SEEDS whose run has OUTCOME, in
# OUT; dies if none.
first() {
    out=$1 seeds=$2 want=$3; shift 3
    for s in $seeds; do
        rm -rf "${out:?}"
        prun "$out" --seed "$s" "$@"
        got=$(field "$out/result.json" outcome)
        [ "$got" != "$want" ] || { echo "$(basename "$out"): seed $s: $(field "$out/result.json" message)"; return 0; }
    done
    die "$(basename "$out"): no $want in seeds $seeds"
}
# story RUNDIR: the JSON story in RUNDIR.story and the event log in RUNDIR.events.
story() {
    st=0; timeout 120 "$PATINA" explain "$1" --format json >"$1.story" 2>"$1.err" || st=$?
    [ "$st" = 0 ] || die "explain $1: exit $st ($(cat "$1.err"))"
    "$PATINA" log events "$1" >"$1.events"
}
# check RUNDIR CASE: the case's facts, from the run (tests/cli/explain-facts.py).
check() { python3 -I "$(dirname "$0")/explain-facts.py" "$1" "$2" "$PATINA" || die "$2: the story"; }

first "$RUNS/jobs" "$(seq 1 64)" failure -- "$G/examples/jobs"
story "$RUNS/jobs"; check "$RUNS/jobs" thread
first "$RUNS/acklog" "$(seq 1 64)" violation --crash machine -- "$G/examples/acklog"
story "$RUNS/acklog"; check "$RUNS/acklog" crash
for n in primary backup; do printf '[node.%s]\ncmd = ["python3", "/guest/kv.py", "%s", "bug"]\n' $n $n; done >"$RUNS/kv.toml"
first "$RUNS/kv" "$(seq 1 64)" failure --config "$RUNS/kv.toml" --mount "$G":/guest:copy -- python3 /guest/kv.py driver
story "$RUNS/kv"; check "$RUNS/kv" nodes
for n in n1 n2 n3; do printf '[node.%s]\ncmd = ["python3", "/guest/q3.py", "%s", "nofence"]\n' $n $n; done >"$RUNS/q3.toml"
first "$RUNS/q3" "$(seq 1 64)" failure --config "$RUNS/q3.toml" --faults net --fault partition-gap-ms=1000..6000 \
    --fault partition-ms=1000..6000 --mount "$G":/guest:copy -- python3 /guest/q3.py driver 60
story "$RUNS/q3"; check "$RUNS/q3" partition

# The observed replay is the run, for every run of three sweeps kept whole (explain fails as
# nondeterministic otherwise).
sweep() {
    out=$1; shift
    st=0; timeout 600 "$PATINA" sweep -j 4 --keep all --out "$out" "$@" >"$out.txt" 2>&1 || st=$?
    [ -f "$out/report.json" ] || die "sweep $out: no report (exit $st)"
}
for e in jobs acklog bank ledger serve stats-cp upcase kvlog; do
    sweep "$RUNS/sw-$e" --seeds 1..3 --crash machine --fault net-reset-permille=50 -- "$G/examples/$e"
done
for n in primary backup; do printf '[node.%s]\ncmd = ["python3", "/guest/kv.py", "%s"]\n' $n $n; done >"$RUNS/kv-ok.toml"
sweep "$RUNS/sw-kv" --seeds 1..3 --config "$RUNS/kv-ok.toml" --mount "$G":/guest:copy -- python3 /guest/kv.py driver
sweep "$RUNS/sw-points" --seeds 1..6 -- "$G/rw-races" lms
n=0
for r in "$RUNS"/sw-*/seed-*; do
    st=0; timeout 120 "$PATINA" explain "$r" >"$r.txt" 2>&1 || st=$?
    [ "$st" = 0 ] || die "explain $r: exit $st ($(tail -2 "$r.txt"))"
    n=$((n + 1))
done
echo "observed replay identical to the run: $n runs"
