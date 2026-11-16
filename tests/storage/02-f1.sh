# 2. F1 (partial create not recoverable). Known seeds from the 300-seed sweeps: 5 under
# --crash machine:3, 3 under --crash process:3. The kept post-crash tree, copied out, makes
# the native harness fail the same way; with FJ_WIPE_PARTIAL=1 the same seeds proceed.
# The seeds depend on the host's libc and CPU (they were found on the development host), so
# this is an area check, not a quick one.
#@ tier=area budget=15
. "$(dirname "$0")/lib/common.inc"
for c in "machine:3 5" "process:3 3"; do
    set -- $c
    o=$RUNS/f1-$1-$2
    run fjall-harness "$o" "$2" --crash "$1" -- /guest/fjall-harness-debug
    [ "$(field "$o/outcome.json" detail)" = "INVARIANT open-after-crash" ] || die "$c: $(field "$o/outcome.json" detail)"
    # The tree the failing incarnation started from: the last crash's post-crash tree.
    k=$(jq '.crashes[-1].incarnation' "$o/outcome.json")
    native_fjall fjall-harness-debug "$o/inc-$k/post-crash" "$o/native" >"$o/native.txt"
    grep -q '^INVARIANT open-after-crash' "$o/native.txt" || die "$c native: $(tail -2 "$o/native.txt")"
    rm -rf "$o/native"
    w=$RUNS/f1-wipe-$1-$2
    run fjall-harness "$w" "$2" --env FJ_WIPE_PARTIAL=1 --crash "$1" -- /guest/fjall-harness-debug
    [ "$(field "$w/outcome.json" class)" = ok ] || die "$c with FJ_WIPE_PARTIAL=1: $(field "$w/outcome.json" detail)"
    echo "F1 $1 seed $2: $(field "$o/outcome.json" detail); native: $(grep -v '^INVARIANT' "$o/native.txt" | tail -1); FJ_WIPE_PARTIAL=1: ok"
done
