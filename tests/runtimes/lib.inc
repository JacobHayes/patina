# Shared helpers for the scripts of this area (sourced). Environment from ./check: PATINA,
# RUNS. The four workloads have their own guest directories under $W.
: "${PATINA:?}" "${RUNS:?}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=${PATINA_WORKLOADS:?}
# Sweeps: 4 runs at a time (tests/storage/lib/sweep.sh).
export SWEEP_JOBS=${SWEEP_JOBS:-4}
# Guest output and boundary logs stay small: a soft limit for every run of these scripts
# (a runaway log ends the run as internal, it cannot fill the disk).
ulimit -S -f 2000000
export SWEEP_FSIZE=2000000
FAILS=0
. "$(dirname "${BASH_SOURCE[0]}")/../json.inc"
die() { echo "FAIL: $*"; exit 1; }
# fail MSG: record a failure and keep collecting evidence; `finish` exits 1.
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
finish() {
    if [ "$FAILS" -gt 0 ]; then echo "$FAILS check(s) failed"; exit 1; fi
    echo "all checks passed"
}

# run WORKLOAD OUT SEED [patina options] -- /guest/cmd args: one run (OUT is replaced).
run() {
    wl=$1; out=$2; seed=$3; shift 3
    rm -rf "${out:?}"; mkdir -p "$(dirname "$out")"
    timeout 900 "$PATINA" run --seed "$seed" --out "$out" --mount "$W/$wl":/guest:copy "$@" >/dev/null 2>"$out.err" \
        || [ -f "$out/result.json" ] || die "patina run $* (seed $seed): exit $? ($(tail -2 "$out.err"))"
    rm -f "$out.err"
}

# verify WORKLOAD OUT SEED RUNS VARY [patina options] -- cmd: `patina verify`; then, independently of
# its verdict, one digest, one outcome class and one stdout over all run directories.
# Prints "seed S: N identical runs (VARY), class C, digest D". Returns 1 on any difference.
verify() {
    wl=$1; out=$2; seed=$3; runs=$4; vary=$5; shift 5
    rm -rf "${out:?}"; mkdir -p "$(dirname "$out")"
    if ! timeout 7200 "$PATINA" verify --seed "$seed" --runs "$runs" --vary "$vary" --out "$out" --mount "$W/$wl":/guest:copy "$@" \
        >"$out.verify.txt" 2>&1 && ! grep -q '^identical: ' "$out.verify.txt"; then
        echo "verify $wl seed $seed: patina verify exit status non-zero: $(tail -3 "$out.verify.txt")"
        return 1
    fi
    nd=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    nc=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/result.json" outcome; done | sort -u | wc -l)
    ns=$(for i in $(seq 0 $((runs - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$nd" = 1 ] && [ "$nc" = 1 ] && [ "$ns" = 1 ] || {
        echo "verify $wl seed $seed: $nd digests, $nc classes, $ns stdout files over $runs runs"
        return 1
    }
    echo "seed $seed: $runs identical runs ($vary), class $(field "$out/run-0/result.json" outcome), digest $(field "$out/run-0/result.json" digest), faults $(field "$out/run-0/result.json" faults.injected)"
}

# verify_seeds WORKLOAD NAME VARY "SEEDS" [patina options] -- cmd: verify each seed ($VERIFY_RUNS runs,
# default 3), the seeds in parallel; prints each line; returns the number of seeds that were not identical.
verify_seeds() {
    wl=$1; name=$2; vary=$3; seeds=$4; shift 4
    for s in $seeds; do
        (verify "$wl" "$RUNS/$name/seed-$s" "$s" "${VERIFY_RUNS:-3}" "$vary" "$@" >"$RUNS/$name.seed-$s.txt" 2>&1 \
            || echo "NOT IDENTICAL" >>"$RUNS/$name.seed-$s.txt") &
    done
    wait
    bad=0
    for s in $seeds; do
        cat "$RUNS/$name.seed-$s.txt"
        grep -q "NOT IDENTICAL" "$RUNS/$name.seed-$s.txt" && bad=$((bad + 1))
        # keep the first run of each seed (evidence), drop the others (disk)
        for i in $(seq 1 $((${VERIFY_RUNS:-3} - 1))); do rm -rf "${RUNS:?}/$name/seed-$s/run-$i"; done
    done
    return $bad
}

# sweep NAME WORKLOAD SEEDS -- options -- cmd: tests/storage/lib/sweep.sh into $RUNS/NAME.
sweep() {
    name=$1; shift
    SWEEP_OUT=$RUNS/$name "$HERE/../storage/lib/sweep.sh" "$@" >"$RUNS/$name.table" 2>&1
    tail -1 "$RUNS/$name.table"
}
# count NAME CLASS: runs of the sweep with that outcome class.
count() { awk -F'\t' -v c="$2" 'NR>1 && $2==c' "$RUNS/$1/summary.tsv" | wc -l; }
# stalls NAME: runs of the sweep that ended unsupported, stop compute-stall.
stalls() { jq -r .stop "$RUNS/$1"/outcomes/*.json | awk '$0 == "compute-stall" {n++} END {print n + 0}'; }
# digests NAME: distinct digests among the sweep's ok runs.
digests() { awk -F'\t' 'NR>1 && $2=="ok" {print $4}' "$RUNS/$1/summary.tsv" | sort -u | wc -l; }
# ok_seeds NAME N: the first N seeds whose run was ok.
ok_seeds() { awk -F'\t' -v n="$2" 'NR>1 && $2=="ok" && n-- > 0 {print $1}' "$RUNS/$1/summary.tsv" | tr '\n' ' '; }

# netf WORKLOAD NAME PATTERN "SEEDS" [patina options] -- cmd: one run per seed with a network
# fault; prints per seed the class, wall time, wire counters and the first stdout line matching
# PATTERN. Returns 1 unless some seed's run was ok and printed a matching line (the program saw
# the fault).
netf() {
    wl=$1; name=$2; pat=$3; seeds=$4; shift 4
    seen=0
    for s in $seeds; do
        o=$RUNS/$name-$s
        run "$wl" "$o" "$s" "$@"
        c=$(field "$o/result.json" outcome)
        k=$(grep -c -- "$pat" "$o/inc-0/stdout") || [ $? = 1 ]
        echo "seed $s: class $c, wall $(field "$o/result.json" wall_ms) ms, faults $(field "$o/result.json" faults.injected), net $(jq -c '.counters.net | {connections,chunks,resets,blacked_out}' "$o/result.json"); $k lines match: $(grep -m1 -- "$pat" "$o/inc-0/stdout" || [ $? = 1 ])"
        [ "$c" = ok ] && [ "$k" -gt 0 ] && seen=$((seen + 1))
    done
    [ "$seen" -gt 0 ]
}

# stats RUN: per-run numbers from result.json and the boundary log (lib/stats.py).
stats() { python3 -I "$HERE/lib/stats.py" "$PATINA" "$@"; }

# native OUT GUESTDIR cmd...: the same command outside the runtime, in the sandbox a run gets
# (`patina __native`, GUESTDIR at /guest). stdout to OUT, stderr to OUT.err. Prints the wall
# time in ms.
native() {
    out=$1; guest=$2; shift 2
    t0=$(date +%s%N)
    timeout 300 "$PATINA" __native --mount "$guest:/guest" -- "$@" >"$out" 2>"$out.err" || echo "native exit $?" >>"$out.err"
    t1=$(date +%s%N)
    echo $(((t1 - t0) / 1000000))
}

# no_leftovers DIR: no process of this user still belongs to a run under DIR.
no_leftovers() {
    # leftovers.py exits 1 when it lists processes; exit 1 with no list is its own failure.
    rc=0; left=$(python3 -I "$HERE/../leftovers.py" "$@") || rc=$?
    [ -z "$left" ] || die "processes left from $1: $left"
    [ "$rc" = 0 ] || die "leftovers.py failed (exit $rc)"
    mounts=$(findmnt -rn -o TARGET) || die "findmnt failed"
    m=$(printf '%s\n' "$mounts" | awk '/patina/ {n++} END {print n + 0}')
    [ "$m" = 0 ] || die "$m mounts mention patina"
}
