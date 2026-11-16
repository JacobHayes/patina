# 2. F1 (partial create not recoverable). Under --crash machine:3 and --crash process:3, seeds
# 1-100 are searched for the violation open-after-crash (a few percent of seeds reach it). For the
# first seed whose kept post-crash tree, copied out, makes the native harness fail the same
# way, FJ_WIPE_PARTIAL=1 must let the same seed proceed. The rate depends on the schedule
# and the guest build, so this is an area check, not a quick one.
#@ tier=area budget=30
. "$(dirname "$0")/lib/common.inc"
for crash in machine:3 process:3; do
    n=f1-${crash%%:*}
    seeds=$(matches "$n" '^open-after-crash: ' fjall-harness 1-100 -- --crash "$crash" -- /guest/fjall-harness-debug)
    [ -n "$seeds" ] || die "$crash: no seed of 1-100 reached open-after-crash ($(tail -1 "$RUNS/$n.table"))"
    found=
    for s in $seeds; do
        o=$RUNS/$n/run-$s
        # The tree the failing incarnation started from: the last crash's post-crash tree.
        k=$(jq '.crashes[-1].incarnation' "$o/result.json")
        native_fjall fjall-harness-debug "$o/inc-$k/post-crash" "$o/native" >"$o/native.txt"
        rm -rf "$o/native"
        grep -q '^INVARIANT open-after-crash' "$o/native.txt" && { found=$s; break; }
    done
    [ -n "$found" ] || die "$crash: the native harness recovered every kept tree (seeds $(echo $seeds))"
    w=$RUNS/f1-wipe-$n-$found
    run fjall-harness "$w" "$found" --env FJ_WIPE_PARTIAL=1 --crash "$crash" -- /guest/fjall-harness-debug
    [ "$(field "$w/result.json" outcome)" = ok ] || die "$crash seed $found with FJ_WIPE_PARTIAL=1: $(field "$w/result.json" message)"
    echo "F1 $crash: seeds $(echo $seeds) of 1-100; seed $found native: $(grep '^INVARIANT' "$o/native.txt" | tail -1); FJ_WIPE_PARTIAL=1: ok"
done
