# 7. Determinism under each finding's settings (F1-F6, as in the earlier checks in this area):
# one seed of each run twice (the second on another CPU, both beside busy loops: --vary
# cpu,load) gives identical digests, outcomes, output and post-crash tree digests (patina
# verify compares the crash records, which carry each post-crash tree's digest). The seeds
# are samples: the comparison holds whether or not the seed fails. The quick tier takes F1
# (machine and process crashes) and F5; the area tier every finding's.
#@ tier=quick budget=20
. "$(dirname "$0")/lib/common.inc"
v() {
    name=$1; seed=$2; shift 2
    timeout 900 "$PATINA" verify --seed "$seed" --runs 2 --vary cpu,load --out "$RUNS/$name" \
        --mount "$W/fjall-harness":/guest:copy "$@" >"$RUNS/$name.txt" 2>&1 || grep -q '^identical: ' "$RUNS/$name.txt" || die "$name: $(tail -3 "$RUNS/$name.txt")"
    echo "$name seed $seed: $(grep '^run 0' "$RUNS/$name.txt" | awk '{print $9, $10}'); $(tail -1 "$RUNS/$name.txt" | cut -d' ' -f1-3)"
    rm -rf "${RUNS:?}/$name"
}
v f1-machine3 5 --fault crash-permille=3 -- /guest/fjall-harness-debug
v f1-process3 3 --faults kill --fault crash-permille=3 -- /guest/fjall-harness-debug
v f5 3 --fault fs-short-permille=20 -- /guest/fjall-harness-debug
[ "${CHECK_TIER:-}" != quick ] || exit 0
v f2 634 --env FJ_N=2000 --faults buggify --fault crash-permille=1 -- /guest/fjall-harness-debug
v f6 946 --env FJ_N=2000 --faults buggify --fault crash-permille=1 -- /guest/fjall-harness-debug
v f3 40 --env FJ_N=1000 --faults buggify --env FJ_LOG=2 --env FJ_WIPE_PARTIAL=1 --config "$("$PATINA_CFG" time-limit=400)" \
    --fault fs-error-permille=3 --fault crash-permille=2 -- /guest/fjall-harness-debug
v f4 6 --fault fsync-error-at=61 --fault crash-permille=3 -- /guest/fjall-harness-debug
