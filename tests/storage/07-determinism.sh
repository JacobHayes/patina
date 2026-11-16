# 7. Determinism of findings: each failing seed of items 2-6 (and F6) re-run 3 times with
# --vary cpu,load gives identical digests, outcomes, output and post-crash tree digests
# (patina verify compares the crash records, which carry each post-crash tree's digest).
#@ tier=quick budget=20
. "$(dirname "$0")/lib/common.inc"
v() {
    name=$1; seed=$2; shift 2
    timeout 900 "$PATINA" verify --seed "$seed" --runs 3 --vary cpu,load --out "$RUNS/$name" \
        --guest "$W/fjall-harness" "$@" >"$RUNS/$name.txt" 2>&1 || die "$name: $(tail -3 "$RUNS/$name.txt")"
    echo "$name seed $seed: $(grep '^run 0' "$RUNS/$name.txt" | awk '{print $9, $10}'); $(tail -1 "$RUNS/$name.txt" | cut -d' ' -f1-3)"
    rm -rf "$RUNS/$name"
}
v f1-machine3 5 --crash machine:3 -- /guest/fjall-harness-debug
v f1-process3 3 --crash process:3 -- /guest/fjall-harness-debug
v f2 634 --env FJ_N=2000 --env FJ_BUGGIFY=1 --crash machine:1 -- /guest/fjall-harness-debug
v f6 946 --env FJ_N=2000 --env FJ_BUGGIFY=1 --crash machine:1 -- /guest/fjall-harness-debug
v f3 40 --env FJ_N=1000 --env FJ_BUGGIFY=1 --env FJ_LOG=2 --env FJ_WIPE_PARTIAL=1 --vtime-limit-s 400 \
    --fault fs-error-permille=3 --crash machine:2 -- /guest/fjall-harness-debug
v f4 6 --fault fsync-error-at=61 --crash machine:3 -- /guest/fjall-harness-debug
v f5 3 --fault short-permille=20 -- /guest/fjall-harness-debug
