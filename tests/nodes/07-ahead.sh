# 7. Nodes: what keeps a run alive whose threads all wait with no deadline
# (tests/guests/nodes/ahead.py). The seed's kill of a node ahead: the run goes on to it, and the
# waiting driver sees its connection end; the kill's down time is drawn from the node default
# (down-ms 1..5 s). A node's restart ahead: the driver accepts the restarted node's connection.
# A partition's heal ahead: the request the cut held is delivered and answered. With
# net-links=driver the seed's partition separates the driver from a node, and the driver's own
# control calls (`patina ctl`, `patina.control`) still answer inside it. Only a partition's
# start ahead, or a kill after the driver marked faults-done: the run is deadlocked. A
# faults-done mark inside a partition heals it at once.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/07-ahead; mkdir -p "$o"
rm -f "$o/b.toml" "$o/exit.toml"
conf "$o/b.toml" b python3 /guest/ahead.py b
conf "$o/exit.toml" b python3 /guest/ahead.py b exit
printf 'restart = "always"\n' >>"$o/exit.toml"
deadlock() {
    r=$(field "$1/result.json" outcome)/$(field "$1/result.json" stop)
    [ "$r" = liveness/deadlock ] || die "$2: $r: $(field "$1/result.json" message)"
}

run_ok "$o/kill" 1 --config "$o/b.toml" --faults kill --fault crash-gap-ms=2000..3000 -- python3 /guest/ahead.py driver kill
[ "$(cat "$o/kill/inc-0/stdout")" = "kill: the connection ended" ] || die "kill: $(cat "$o/kill/inc-0/stdout")"
d=$(field "$o/kill/result.json" nodes.list.1.downs.0)
python3 -I -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(not (d["how"] == "killed" and 1000 <= d["down_ms"] < 5000))' "$d" \
    || die "kill: the down: $d"
echo "a kill ahead: the run went on to it; $d"

run_ok "$o/restart" 1 --config "$o/exit.toml" -- python3 /guest/ahead.py driver restart
[ "$(cat "$o/restart/inc-0/stdout")" = "restart: back inc=1" ] || die "restart: $(cat "$o/restart/inc-0/stdout")"
echo "a restart ahead: $(cat "$o/restart/inc-0/stdout")"

parts="--fault net-links=driver --fault partition-gap-ms=2000..2000 --fault partition-ms=5000..5000"
run_ok "$o/heal" 1 --config "$o/b.toml" $parts -- python3 /guest/ahead.py driver heal
[ "$(cat "$o/heal/inc-0/stdout")" = "heal: pong" ] || die "heal: $(cat "$o/heal/inc-0/stdout")"
p=$(field "$o/heal/result.json" nodes.partitions.0)
python3 -I -c 'import json,sys; p=json.loads(sys.argv[1]); sys.exit(not (sorted(p["a"] + p["b"]) == ["b", "driver"] and p["acted"]))' "$p" \
    || die "heal: the partition: $p"
n=$("$PATINA" log events "$o/heal" --types sdk | grep -c '"op":"control"')
[ "$n" = 3 ] || die "heal: $n control calls in the events"
echo "a heal ahead: the held ping answered; the seed's partition $p; the driver's control calls answered inside it"

run_ok "$o/done" 1 --config "$o/b.toml" $parts -- python3 /guest/ahead.py driver done
[ "$(cat "$o/done/inc-0/stdout")" = "done: pong" ] || die "done: $(cat "$o/done/inc-0/stdout")"
echo "faults-done inside a partition: healed at once"

run "$o/cut" 1 --config "$o/b.toml" $parts -- python3 /guest/ahead.py driver kill >/dev/null
deadlock "$o/cut" "only a partition's start ahead"
run "$o/quiet" 1 --config "$o/b.toml" --faults kill --fault crash-gap-ms=2000..3000 -- python3 /guest/ahead.py driver quiet >/dev/null
deadlock "$o/quiet" "a kill after faults-done"
echo "only a partition's start ahead, or a kill after faults-done: deadlock"
