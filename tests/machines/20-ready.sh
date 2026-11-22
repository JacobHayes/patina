# 20. Machines: `ready` probes (sup::ready). A slow-starting server (slow.py: 20 synced writes,
# 0.1 s apart, before it serves phases.py's store; a failed one ends it) under fsync errors.
# Without a probe the seed's faults reach its start: a search of seeds finds a run where the
# server ended at its start. With `ready = "patina wait :7000"` none does over the same seeds:
# every run is ok and no fault comes before the event that opens the window; the server's first
# ready time is in result.json, and replay is identical. Crash points count only after ready:
# `crash-at=1@srv` crashes it after its ready time (without the probe, during its start). A
# probe on main alone (one machine, `sh -c 'server & client'`) holds the faults the same way.
# A probe that never passes ends `error`, stop `ready`, naming the machine. A runner killed
# before its machine is ready starts again: its probe keeps polling (here it kills its own
# runner once, then waits for the port).
#@ tier=quick,release budget=40 slots=1
. "$(dirname "$0")/lib.inc"
o=$RUNS/20-ready; mkdir -p "$o"
rm -f "$o"/*.toml
# srv.toml and srv-ready.toml: the machine, without and with its probe; plain.toml and
# ready.toml add main, unfaulted: it runs only the test.
conf "$o/srv.toml" srv python3 /guest/slow.py
cp "$o/srv.toml" "$o/srv-ready.toml"
echo 'ready = "patina wait :7000"' >>"$o/srv-ready.toml"
cp "$o/srv.toml" "$o/plain.toml"; main_unfaulted "$o/plain.toml"
cp "$o/srv-ready.toml" "$o/ready.toml"; main_unfaulted "$o/ready.toml"
F=(--fault fsync-error-permille=50)
W=(python3 /guest/phases.py work 5 srv)

# Without the probe: a fault in the server's start, found by a search of seeds.
s=1
while :; do
    c=$(run "$o/plain" $s --config "$o/plain.toml" "${F[@]}" -- "${W[@]}")
    [ "$c" != failure ] || break
    s=$((s + 1)); [ $s -le 16 ] || die "seeds 1-16: no fault reached the server's start"
done
[ "$(field "$o/plain/result.json" machines.list.1.end.exit)" = 1 ] || die "seed $s: $(field "$o/plain/result.json" message)"
echo "without ready: seed $s ended the server at its start"

# With it, seeds 1..s: ok, no fault before the window opened.
for k in $(seq 1 $s); do
    run_ok "$o/ready-$k" $k --config "$o/ready.toml" "${F[@]}" -- "${W[@]}"
    "$PATINA" log events "$o/ready-$k" --types machine,fault,crash >"$o/ready-$k.ev" || die "log events"
    python3 -I - "$o/ready-$k.ev" <<'PY' || die "seed $k: a fault before the window opened"
import json, sys
opened = None
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e["type"] == "machine" and e.get("event") == "ready" and e.get("faults") == "begin":
        opened = e["seq"]
    elif e["type"] in ("fault", "crash"):
        assert opened is not None and e["seq"] > opened, e
assert opened is not None
PY
done
r=$(field "$o/ready-$s/result.json" ready.srv) m=$(field "$o/ready-$s/result.json" ready.main)
[ "$r" -gt "$m" ] || die "ready times: srv $r, main $m"
"$PATINA" replay "$o/ready-$s" >"$o/replay.txt" 2>&1 || die "replay: $(tail -3 "$o/replay.txt")"
grep -q '^identical' "$o/replay.txt" || die "replay: $(cat "$o/replay.txt")"
echo "with ready: seeds 1-$s ok, no fault before the window; srv ready at $r ms; replay identical"

# Crash points: the first one is after ready.
for v in plain ready; do
    run_ok "$o/at-$v" 1 --config "$o/$v.toml" --faults crash@srv --fault crash-at=1@srv -- "${W[@]}"
done
p=$(field "$o/at-plain/result.json" machines.list.1.downs.0.at_ms)
a=$(field "$o/at-ready/result.json" machines.list.1.downs.0.at_ms)
r=$(field "$o/at-ready/result.json" ready.srv)
[ "$a" -ge "$r" ] && [ "$p" -lt "$r" ] || die "crash at the first point: $p without ready, $a with (ready at $r)"
echo "crash-at=1: at $p ms without ready, $a ms with (ready at $r ms)"

# A probe on main alone.
printf '[machine.main]\nready = "patina wait :7000"\n' >"$o/main.toml"
for k in $(seq 1 $s); do
    run_ok "$o/main-$k" $k --config "$o/main.toml" "${F[@]}" -- sh -c 'python3 /guest/slow.py & python3 /guest/phases.py work 5 127.0.0.1'
done
r=$(field "$o/main-$s/result.json" ready.main)
[ "$r" != null ] || die "main: never ready"
# With a machine that waits too: main's command starts once srv is ready, before main is.
{ cat "$o/srv-ready.toml"; cat "$o/main.toml"; } >"$o/both.toml"
run_ok "$o/both" 1 --config "$o/both.toml" "${F[@]}" -- sh -c 'python3 /guest/slow.py & python3 /guest/phases.py work 5 127.0.0.1 && python3 /guest/phases.py work 5 srv'
r=$(field "$o/both/result.json" ready.main)
[ "$r" != null ] || die "main and srv: main never ready"
# Main's command ending before main is ready ends the run as a machine's run does.
c=$(run "$o/quick" 1 --config "$o/main.toml" -- true)
[ "$c/$(field "$o/quick/result.json" stop)" = error/ready ] || die "main's command ended first: $c"
echo "a probe on main: seeds 1-$s ok; with srv's too, ok; main's command ending first: error (ready)"

# A probe that never passes.
conf "$o/never.toml" srv python3 /guest/phases.py serve
echo 'ready = ["test", "-e", "/work/never"]' >>"$o/never.toml"; main_unfaulted "$o/never.toml"
c=$(run "$o/never" 1 --config "$o/never.toml" -- "${W[@]}")
[ "$c/$(field "$o/never/result.json" stop)" = error/ready ] || die "never ready: $c: $(field "$o/never/result.json" message)"
case $(field "$o/never/result.json" message) in *srv*) ;; *) die "never ready: the message does not name srv" ;; esac
[ "$(field "$o/never/result.json" ready.srv)" = null ] || die "never ready: a ready time"
echo "a probe that never passes: error (ready), naming srv"

# A runner killed while its machine waits: the probe runs again, and the machine is ready.
cp "$o/srv.toml" "$o/kick.toml"
cat >>"$o/kick.toml" <<'EOF'
ready = ["sh", "-c", "test -e /work/kicked || { touch /work/kicked; kill -9 $PPID; }; exec patina wait :7000"]
EOF
main_unfaulted "$o/kick.toml"
run_ok "$o/kick" 1 --config "$o/kick.toml" -- "${W[@]}"
r=$(field "$o/kick/result.json" ready.srv)
[ "$r" != null ] || die "a killed runner: srv never ready"
echo "a runner killed once: srv ready at $r ms"
