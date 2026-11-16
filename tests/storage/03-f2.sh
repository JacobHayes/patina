# 3. F2 (journal-entry assertion in recovery, debug only) and F6 (batch atomicity broken with
# no injected fault), from the 1000-seed debug sweep with FJ_N=2000 FJ_BUGGIFY=1
# --crash machine:1 (F2: seed 634, F6: seed 946). Each is about one seed in 1,000 and needs
# the schedule that sweep ran: 24 CPUs and no pause points (at the default 4 CPUs neither
# appeared in 1,000 seeds), so the settings are given here and the seeds are named. The seeds
# depend on the host's libc and CPU, so this is an area check, not a quick one.
#@ tier=area budget=15
. "$(dirname "$0")/lib/common.inc"
opts="--config $("$PATINA_CFG" pause-points=false) --cpus 24 --env FJ_N=2000 --env FJ_BUGGIFY=1 --crash machine:1"
o=$RUNS/f2-debug-634
run fjall-harness "$o" 634 $opts -- /guest/fjall-harness-debug
[ "$(field "$o/result.json" message)" = "exit status 101" ] || die "F2 debug: $(field "$o/result.json" message)"
grep -q 'journal/entry.rs' "$o/inc-1/stderr" || die "F2: panic not in the journal entry decoder"
r=$RUNS/f2-release-634
run fjall-harness "$r" 634 $opts -- /guest/fjall-harness-release
[ "$(field "$r/result.json" outcome)" = ok ] || die "F2 release: $(field "$r/result.json" message)"
# Native: the debug harness panics on the kept tree, the release harness recovers it.
for b in debug release; do
    mkdir -p "$o/native-$b"; cp -a "$o/inc-0/post-crash" "$o/native-$b/tree"
    set +e
    FJ_ROOT=$o/native-$b/tree/fjtest timeout 120 "$W/fjall-harness/fjall-harness-$b" >/dev/null 2>"$o/native-$b.txt"
    echo $? >"$o/native-$b.rc"; set -e
    rm -rf "$o/native-$b"
done
[ "$(cat "$o/native-debug.rc")" = 101 ] || die "F2 native debug: exit $(cat "$o/native-debug.rc")"
[ "$(cat "$o/native-release.rc")" = 0 ] || die "F2 native release: exit $(cat "$o/native-release.rc")"
echo "F2 seed 634: debug exit 101 (journal entry assertion), release ok; native: debug 101, release 0"
f=$RUNS/f6-946
run fjall-harness "$f" 946 $opts -- /guest/fjall-harness-debug
[ "$(field "$f/result.json" message)" = "INVARIANT batch-atomic-across-keyspaces" ] || die "F6: $(field "$f/result.json" message)"
[ "$(jq '.faults.injected - (.faults.counts.crash.injected // 0)' "$f/result.json")" = 0 ] || die "F6: expected no injected fault but the crash"
native_fjall fjall-harness-debug "$f/inc-0/post-crash" "$f/native" >"$f/native.txt"
grep -q '^INVARIANT batch-atomic-across-keyspaces' "$f/native.txt" || die "F6 native: $(tail -2 "$f/native.txt")"
rm -rf "$f/native"
echo "F6 seed 946: batch atomicity broken with no injected fault; native harness agrees on the kept tree"
