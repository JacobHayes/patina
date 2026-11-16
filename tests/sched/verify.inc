# verify_all LABEL [patina options]: for each guest and seed ($VERIFY_SEEDS, default 1), $VERIFY_RUNS
# runs (default 4) varying CPU and host load must be identical (patina verify exits 0, and
# independently: one digest, one stdout over the run directories); the first run of each also
# passes check_result. (the recorded run used seeds 1-5 x 20 runs: docs/EVIDENCE.md the scheduler; the
# evidence tier's matrix covers volume.)
verify_all() {
    label=$1; shift
    mkdir -p "$RUNS/$label"
    for g in $GUESTS; do
        for seed in ${VERIFY_SEEDS:-1}; do
            runs=${VERIFY_RUNS:-4}
            out=$RUNS/$label/$g-s$seed
            timeout 1200 "$PATINA" verify "$@" --seed "$seed" --runs "$runs" --vary cpu,load --out "$out" \
                --mount "$PATINA_GUESTS":/guest:copy -- "/guest/$g" >"$out.verify.txt" 2>&1 || grep -q '^identical: ' "$out.verify.txt" || die "$g seed $seed: verify exit $? ($(tail -3 "$out.verify.txt"))"
            n=$(for i in $(seq 0 $((runs - 1))); do field "$out/run-$i/outcome.json" digest; done | sort -u | wc -l)
            [ "$n" = 1 ] || die "$g seed $seed: $n distinct digests"
            n=$(for i in $(seq 0 $((runs - 1))); do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
            [ "$n" = 1 ] || die "$g seed $seed: $n distinct stdout files"
            check_result "$out/run-0" "$g"
            echo "$label $g seed $seed: $runs identical runs, digest $(field "$out/run-0/outcome.json" digest), switches $(field "$out/run-0/outcome.json" sched.switches), cpus $(grep -o 'cpu [0-9]*' "$out.verify.txt" | sort -u | wc -l)"
        done
    done
}
