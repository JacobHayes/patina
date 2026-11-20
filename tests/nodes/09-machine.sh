# 9. Nodes: a node's machine crash (tests/guests/nodes/disk.py). The driver crashes node a's
# machine with `node kill a` and starts it again, five times: what a fsynced survives every
# crash, what it did not can be lost (lost in some of the crashes here), node b's unsynced
# write is untouched by a's crashes; an established connection to a sees nothing once the
# kill returns (no end of file, no reset, unlike `node kill a --process` in 05-kill), a
# connect to a while it is down times out rather than being refused, and after the restart
# the old connection gets a reset at its next send. Every disk passes the self-check. The same
# seed is identical under verify, and a run replays identically.
#@ tier=quick budget=60 slots=2
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-machine; mkdir -p "$o"
rm -f "$o/d.toml"; conf "$o/d.toml" a python3 /guest/disk.py a; conf "$o/d.toml" b python3 /guest/disk.py b
run_ok "$o/crash" 1 --config "$o/d.toml" -- python3 /guest/disk.py driver 5
sed 's/^/    /' "$o/crash/inc-0/stdout"
[ "$(field "$o/crash/result.json" self_check.verdict)" = pass ] || die "self-check: $(field "$o/crash/result.json" self_check)"
lost=$(sed -n 's/^unsynced lost in \([0-9]*\) of .*/\1/p' "$o/crash/inc-0/stdout")
[ "${lost:-0}" -ge 1 ] || die "no unsynced write was lost in 5 machine crashes"
n=$("$PATINA" log events "$o/crash" --types node | grep -c '"event":"machine-crash","name":"a".*"by":"script"')
[ "$n" = 5 ] || die "machine-crash events of a: $n"
verify_ok "$o/verify" 2 3 --config "$o/d.toml" -- python3 /guest/disk.py driver 3
st=0; timeout 300 "$PATINA" replay "$o/crash" >"$o/replay.txt" 2>&1 || st=$?
grep -q '^identical' "$o/replay.txt" || die "replay: exit $st: $(head -3 "$o/replay.txt")"
echo "replay: identical"
