# 5. F4 (a failed journal fsync followed by a successful one loses batches from one keyspace
# only), with --fault crash-permille=3: fsync-error-at=50..80 x seeds 1-10 are searched, in that
# order, for the violation batch-atomic-across-keyspaces (a few cells of the 100 x 10 grid reach
# it). For the first such cell the kept tree of the incarnation before the failing one makes
# the native harness fail the same way, and the same seed without the fault passes. Under
# [sched] preempt = "traps": the cells were found there (load-time points reach one too, at
# about twice the search). The cells depend on the schedule and
# the guest build, so this is an area check, not a quick one.
#@ tier=area budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
for n in $(seq 50 80); do
    seeds=$(matches "f4-n$n" '^batch-atomic-across-keyspaces: ' fjall-harness 1-10 -- \
        --config "$("$PATINA_CFG" preempt=traps)" --fault "fsync-error-at=$n" --fault crash-permille=3 -- /guest/fjall-harness-debug)
    for s in $seeds; do
        o=$RUNS/f4-n$n/run-$s
        k=$(jq '.crashes[-1].incarnation' "$o/result.json")
        native_fjall fjall-harness-debug "$o/inc-$k/post-crash" "$o/native" >"$o/native.txt"
        rm -rf "${o:?}/native"
        grep -q '^INVARIANT batch-atomic-across-keyspaces' "$o/native.txt" || continue
        ctl=$RUNS/f4-control-s$s
        run fjall-harness "$ctl" "$s" --config "$("$PATINA_CFG" preempt=traps)" --fault crash-permille=3 -- /guest/fjall-harness-debug
        [ "$(field "$ctl/result.json" outcome)" = ok ] || die "F4 control seed $s: $(field "$ctl/result.json" message)"
        echo "F4 fsync-error-at=$n seed $s: $(grep '^recovery' "$o/inc-$((k + 1))/stderr" | tail -1); native agrees; control ok"
        exit 0
    done
done
die "F4: no cell of fsync-error-at=50..80 x seeds 1-10 reproduced with the native harness agreeing"
