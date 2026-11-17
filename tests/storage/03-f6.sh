# 3. F6 (batch atomicity broken with no injected fault) from a debug sweep with FJ_N=2000
# --buggify --crash machine:1 at 24 CPUs without pause points (seed 2001; 2 seeds in 6,000,
# none at the default 4 CPUs in 2,000, see docs/EVIDENCE.md), so the settings are given here
# and the seed is named; the kept tree makes the native harness fail the same way. F2 (the
# journal-entry assertion) needs a crash in a window of a few crash points, which plain sweeps
# almost never hit; 12-f2.sh finds it by trying every crash point.
# The seed depends on the host's libc and CPU, so this is an area check, not a quick one; it was
# found on x86_64, so the script runs there only.
#@ tier=area budget=15 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
opts="--config $("$PATINA_CFG" pause-points=false) --cpus 24 --env FJ_N=2000 --buggify --crash machine:1"
f=$RUNS/f6-2001
run fjall-harness "$f" 2001 $opts -- /guest/fjall-harness-debug
case "$(field "$f/result.json" message)" in
    batch-atomic-across-keyspaces:*) ;;
    *) die "F6: $(field "$f/result.json" message)" ;;
esac
[ "$(jq '.faults.injected - (.faults.counts.crash.injected // 0)' "$f/result.json")" = 0 ] || die "F6: expected no injected fault but the crash"
native_fjall fjall-harness-debug "$f/inc-0/post-crash" "$f/native" >"$f/native.txt"
grep -q '^INVARIANT batch-atomic-across-keyspaces' "$f/native.txt" || die "F6 native: $(tail -2 "$f/native.txt")"
rm -rf "$f/native"
echo "F6 seed 2001: $(field "$f/result.json" message); native harness agrees on the kept tree"
