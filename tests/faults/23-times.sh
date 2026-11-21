# 23. A restart keeps the work tree's file times. Incarnation 0 sets `f`'s time to 2100 (past
# what some host filesystems hold), writes `a` and `b` 5 s apart, syncs, prints the three
# times, then rewrites `c` until the crash at point 50; incarnation 1 prints them again. Under
# `--faults kill --fault crash-at=50` and `--faults crash --fault crash-at=50` (all three were synced, so both models
# keep them), and as a node's program under `--fault crash-at=50@a` (its boot 1 on a new
# disk), each reads after the restart as it did before and none as the virtual file epoch;
# the process-crash run replays identical. About 3 s.
#@ tier=quick budget=15 slots=2
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/23
prog='echo "inc=${PATINA_INCARNATION:-0}"
if [ -z "$PATINA_INCARNATION" ]; then
  echo f >f; touch -d "2100-01-01 00:00:00" f
  sleep 5; echo a >a; sleep 5; echo b >b; sync  # lint-allow: sleep — virtual time in the guest, which costs no wall time
  stat -c "%n %y" a b f
  i=0; while [ $i -lt 200 ]; do echo $i >c; i=$((i+1)); done
else
  stat -c "%n %y" a b f
fi'
for kind in process machine; do
    run "$d/$kind" 1 $([ $kind = process ] && echo --faults kill || echo --faults crash) --fault crash-at=50 -- /bin/sh -c "$prog"
    [ "$(field "$d/$kind/result.json" faults.counts.crash.injected)" = 1 ] || die "$kind: no crash"
    before=$(grep -E '^[abf] ' "$d/$kind/inc-0/stdout")
    after=$(grep -E '^[abf] ' "$d/$kind/inc-1/stdout")
    [ "$(echo "$before" | wc -l)" = 3 ] || die "$kind: incarnation 0 printed: $before"
    [ "$before" = "$after" ] || die "$kind: times before the crash: $before; after: $after"
    ! echo "$after" | grep -q '2026-01-01 00:00:00.000000000' || die "$kind: a time reads as the epoch: $after"
    echo "$kind crash: a, b and f keep their times ($(echo "$after" | tr '\n' ' '))"
done
run "$d/node" 1 --fault crash-at=50@a --node a="/bin/sh -c '$prog
sleep 1000'" -- /bin/sh -c 'sleep 200'  # lint-allow: sleep — virtual time in the guests, which costs no wall time
[ "$(field "$d/node/result.json" faults.counts.crash.injected)" = 1 ] || die "node: no crash"
before=$(grep -E '^[abf] ' "$d/node/node/a/inc-0/stdout")
after=$(grep -E '^[abf] ' "$d/node/node/a/inc-1/stdout")
[ "$(echo "$before" | wc -l)" = 3 ] || die "node: boot 0 printed: $before"
[ "$before" = "$after" ] || die "node: times before the crash: $before; after: $after"
echo "a node's machine crash: a, b and f keep their times"
"$PATINA" replay "$d/process" >"$d/replay.out" 2>&1 || die "the process-crash run does not replay: $(tail -3 "$d/replay.out")"
echo "the process-crash run replays identical"
