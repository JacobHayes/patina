# 9. Failed fsync end to end: with fsync-error-at=3 (the first record's fsync) and a
# machine crash right after the acknowledgement, the guest that retries fsync until it
# succeeds loses an acknowledged record; the guest that treats the first EIO as fatal is ok.
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/09
# The crash point: just after the fsync of "acks" that follows the failure (from a run
# without crashes; the run before the crash is the same).
run "$d/probe" 1 --fault fsync-error-at=3 -- /guest/ack-log retry
"$PATINA" log ops "$d/probe/boot-1" >"$d/probe.ops"
sed -n 1,12p "$d/probe.ops"
set -- $(python3 -I "$LIB/faults.py" point-after "$d/probe/boot-1" Fsync acks 1)
at=$1 aseq=$2
echo "crash at crash point $at, after the acks fsync at seq $aseq"
for m in ext4-ordered posix-strict; do
    o=$d/retry-$m
    run "$o" 1 --config "$("$PATINA_CFG" fs-model=$m)" --fault fsync-error-at=3 --fault crash-at=$at -- /guest/ack-log retry
    [ "$(jq '.crashes[0].seq' "$o/result.json")" = "$aseq" ] && [ "$(jq '.crashes[0].point' "$o/result.json")" = "$at" ] ||
        die "$m: crashed at seq $(jq '.crashes[0].seq' "$o/result.json") point $(jq '.crashes[0].point' "$o/result.json"), not point $at after seq $aseq"
    echo "$m retry: $(class "$o") $(field "$o/result.json" message); injected $(field "$o/result.json" faults.recent)"
    [ "$(class "$o")" = failure ] && field "$o/result.json" message | grep -q "INVARIANT acked-record-lost" \
        || die "$m: retry-until-success was not caught"
    o=$d/fatal-$m
    run "$o" 1 --config "$("$PATINA_CFG" fs-model=$m)" --fault fsync-error-at=3 --fault crash-at=$at -- /guest/ack-log fatal
    echo "$m fatal: $(class "$o") ($(tail -1 "$o/boot-1/stdout"))"
    [ "$(class "$o")" = ok ] || die "$m: fatal-on-EIO guest: $(class "$o") $(field "$o/result.json" message)"
done
