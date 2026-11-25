# 9. Machines: a machine crash (tests/guests/machines/disk.py). Main crashes machine a's
# machine with `crash a` and starts it again, five times: what a fsynced survives every
# crash, what it did not can be lost (some seed's crashes lose it: searched for), machine b's unsynced
# write is untouched by a's crashes; an established connection to a sees nothing once the
# kill returns (no end of file, no reset, unlike `kill a` in 05-kill), a
# connect to a while it is down times out rather than being refused, and after the restart
# the old connection gets a reset at its next send. Every disk passes the self-check, also one
# that holds a Unix socket's synced file at the crash (a restarted machine's tree has none). The same
# seed is identical under verify, and a run replays identically.
#@ tier=quick budget=60 slots=1.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-machine; mkdir -p "$o"
rm -f "$o/d.toml"; conf "$o/d.toml" a python3 /guest/disk.py a; conf "$o/d.toml" b python3 /guest/disk.py b
# Whether a crash loses the unsynced write is the seed's draw (and the host's interpreter moves
# it), so seeds are searched for a run that loses one; every run searched passes the rest.
lost=0
for seed in $(seq 1 "$FIND_SEEDS"); do
    run_ok "$o/crash" "$seed" --config "$o/d.toml" -- python3 /guest/disk.py main 5
    [ "$(field "$o/crash/result.json" self_check.verdict)" = pass ] || die "self-check (seed $seed): $(field "$o/crash/result.json" self_check)"
    lost=$(sed -n 's/^unsynced lost in \([0-9]*\) of .*/\1/p' "$o/crash/boot-1/stdout")
    [ "${lost:-0}" = 0 ] || break
done
sed 's/^/    /' "$o/crash/boot-1/stdout"
[ "${lost:-0}" -ge 1 ] || die "no unsynced write was lost in 5 machine crashes of seeds 1-$FIND_SEEDS"
echo "seed $seed loses an unsynced write"
n=$("$PATINA" inspect events "$o/crash" --types machine | grep -c '"event":"machine-crash","name":"a".*"by":"script"')
[ "$n" = 5 ] || die "machine-crash events of a: $n"
rm -f "$o/s.toml"; conf "$o/s.toml" b python3 -c "import os, socket, time; socket.socket(socket.AF_UNIX).bind('/work/sock'); os.fsync(os.open('/work', os.O_RDONLY)); time.sleep(30)"
run_ok "$o/sock" 1 --config "$o/s.toml" -- python3 -c "import sys, time; sys.path.insert(0, '/guest'); import patina; time.sleep(1); patina.control('crash b'); patina.control('start b'); time.sleep(1)"
[ "$(field "$o/sock/result.json" self_check.verdict)" = pass ] || die "self-check with a socket's file: $(field "$o/sock/result.json" self_check)"
echo "a machine crash with a Unix socket's file in the tree: self-check pass"
verify_ok "$o/verify" 2 3 --config "$o/d.toml" -- python3 /guest/disk.py main 3
st=0; timeout 300 "$PATINA" replay "$o/crash" >"$o/replay.txt" 2>&1 || st=$?
grep -q '^identical' "$o/replay.txt" || die "replay: exit $st: $(head -3 "$o/replay.txt")"
echo "replay: identical"
