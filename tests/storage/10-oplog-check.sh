# 10. The tracker self-check (patina log ops --check: replay of the whole log = the exported live
# tree) passes on every incarnation of a sample of each storage reproductions workload, crashes included
# (reduced: 4 seeds each).
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
N=${STORAGE_OPLOG_SEEDS:-4}
chk() {
    name=$1; shift
    SWEEP_OUT=$RUNS/$name SWEEP_KEEP=all "$HERE/lib/sweep.sh" "$@" >/dev/null
    k=0
    for s in $(seq 1 "$N"); do
        "$PATINA" log ops --check "$RUNS/$name/run-$s" >"$RUNS/$name/check-$s.txt" 2>&1 || die "$name seed $s: $(tail -2 "$RUNS/$name/check-$s.txt")"
        k=$((k + $(grep -c ': ok (' "$RUNS/$name/check-$s.txt")))
        rm -rf "${RUNS:?}/$name/run-$s"
    done
    echo "$name: $N seeds, $k incarnations, replay = live tree in every one"
}
chk fjall fjall-harness 1-$N -- --fault crash-permille=3 -- /guest/fjall-harness-debug
chk fjall-faults fjall-harness 1-$N -- --faults buggify --fault fs-error-permille=3 --fault crash-permille=2 -- /guest/fjall-harness-debug
chk sqlite-delete c-sqlite 1-$N -- --fault crash-permille=5 -- /guest/sqlite-dur delete full
chk sqlite-wal c-sqlite 1-$N -- --fault crash-permille=5 -- /guest/sqlite-dur wal full
chk w1 rust-threads-files 1-$N -- --fault crash-permille=5 -- /guest/rust-threads-files correct
