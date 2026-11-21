# 9. W1 planted bugs (reduced: 20 seeds per passing case; a caught one searched for, lib/common.inc caught): the correct program passes under both models; variant A
# (no fsync before the acknowledgement) is caught under both; variant B (rename without
# syncing data or directory) is caught under posix-strict and passes under ext4-ordered
# (auto_da_alloc). The 30 s condvar timeout fires in virtual time: the guest reports the full
# wait; with a real wait each of the 40 correct runs would take 30 s, far past the budget.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
for m in ext4-ordered posix-strict; do
    sweep correct-$m rust-threads-files 1-20 -- --config "$("$PATINA_CFG" fs-model=$m)" --fault crash-permille=5 -- /guest/rust-threads-files correct >/dev/null
    [ "$(count correct-$m ok)" = 20 ] || die "correct $m: not all ok"
    caught a-$m 'INVARIANT acked-record-lost' rust-threads-files --config "$("$PATINA_CFG" fs-model=$m)" --fault crash-permille=5 -- /guest/rust-threads-files a
done
sweep b-ext4-ordered rust-threads-files 1-20 -- --fault crash-permille=5 -- /guest/rust-threads-files b >/dev/null
[ "$(count b-ext4-ordered ok)" = 20 ] || die "B fails under ext4-ordered"
caught b-posix-strict 'INVARIANT snapshot-(lost|corrupt)' rust-threads-files --config "$("$PATINA_CFG" fs-model=posix-strict)" --fault crash-permille=5 -- /guest/rust-threads-files b
run rust-threads-files "$RUNS/timeout" 1 -- /guest/rust-threads-files correct
grep -q "idle wait 30000 ms" "$RUNS/timeout/inc-0/stdout" || die "idle wait: $(cat "$RUNS/timeout/inc-0/stdout")"
tables
echo "30 s wait: $(cat "$RUNS/timeout/inc-0/stdout") in $(field "$RUNS/timeout/result.json" wall_ms) ms wall"
