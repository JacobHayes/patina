# 5. F4 (a failed journal fsync followed by a successful one loses batches from one
# keyspace only). From the 100 x 10 sweep: fsync-error-at=61 seed 6 and fsync-error-at=37
# seed 9 with --crash machine:3. Control: the same seeds without the fault pass. The kept
# tree of the incarnation before the failing one makes the native harness fail the same way.
# The seeds depend on the host's libc and CPU (they were found on the development host), so
# this is an area check, not a quick one.
#@ tier=area budget=15
. "$(dirname "$0")/lib/common.inc"
for c in "61 6" "37 9"; do
    set -- $c
    o=$RUNS/f4-n$1-s$2
    run fjall-harness "$o" "$2" --fault fsync-error-at=$1 --crash machine:3 -- /guest/fjall-harness-debug
    [ "$(field "$o/outcome.json" message)" = "INVARIANT batch-atomic-across-keyspaces" ] || die "F4 $c: $(field "$o/outcome.json" message)"
    k=$(jq '.crashes[-1].incarnation' "$o/outcome.json")
    native_fjall fjall-harness-debug "$o/inc-$k/post-crash" "$o/native" >"$o/native.txt"
    grep -q '^INVARIANT batch-atomic-across-keyspaces' "$o/native.txt" || die "F4 $c native: $(tail -2 "$o/native.txt")"
    rm -rf "$o/native"
    ctl=$RUNS/f4-control-s$2
    run fjall-harness "$ctl" "$2" --crash machine:3 -- /guest/fjall-harness-debug
    [ "$(field "$ctl/outcome.json" outcome)" = ok ] || die "F4 control seed $2: $(field "$ctl/outcome.json" message)"
    echo "F4 fsync-error-at=$1 seed $2: $(grep '^recovery' "$o/inc-$((k + 1))/stderr" | tail -1); native agrees; control ok"
done
