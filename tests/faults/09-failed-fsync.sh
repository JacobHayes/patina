# 9. Failed fsync end to end: with fsync-error-at=3 (the first record's fsync) and a
# machine crash right after the acknowledgement, the guest that retries fsync until it
# succeeds loses an acknowledged record; the guest that treats the first EIO as fatal is ok.
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/09
# The crash point: just after the fsync of "acks" that follows the failure (from a run
# without crashes; the run before the crash is the same).
run "$d/probe" 1 --fault fsync-error-at=3 -- /guest/ack-log retry
"$PATINA" oplog dump "$d/probe/inc-0" | sed -n 1,12p
at=$(python3 -I "$LIB/faults.py" seq-after "$d/probe/inc-0" Fsync acks 1)
echo "crash at the first crash point at or after seq $at"
for m in ext4-ordered posix-strict; do
    o=$d/retry-$m
    run "$o" 1 --config "$("$PATINA_CFG" fs-model=$m)" --fault fsync-error-at=3 --crash machine-at:$at -- /guest/ack-log retry
    echo "$m retry: $(class "$o") $(field "$o/outcome.json" message); injected $(field "$o/outcome.json" faults.recent)"
    [ "$(class "$o")" = failure ] && field "$o/outcome.json" message | grep -q "INVARIANT acked-record-lost" \
        || die "$m: retry-until-success was not caught"
    o=$d/fatal-$m
    run "$o" 1 --config "$("$PATINA_CFG" fs-model=$m)" --fault fsync-error-at=3 --crash machine-at:$at -- /guest/ack-log fatal
    echo "$m fatal: $(class "$o") ($(tail -1 "$o/inc-0/stdout"))"
    [ "$(class "$o")" = ok ] || die "$m: fatal-on-EIO guest: $(class "$o") $(field "$o/outcome.json" message)"
done
