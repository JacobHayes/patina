"""The facts of an explained run (tests/cli/14-explain-cases.sh): RUNDIR.story (`patina explain
--format json`) against RUNDIR.events (`patina log events`) and the run's result. Usage:
explain-facts.py RUNDIR CASE PATINA, CASE one of thread, crash, nodes, partition."""
import json
import subprocess
import sys

run, case, patina = sys.argv[1:4]
story = [json.loads(l) for l in open(run + ".story")]
events = [json.loads(l) for l in open(run + ".events")]
result = json.load(open(run + "/result.json"))
header = events[0]
records = [e for e in events if "seq" in e]
lines = [l for l in story if l["kind"] not in ("outcome", "stop")]
stop = story[-1]
assert stop["kind"] == "stop", stop


def full():
    out = subprocess.run([patina, "explain", run, "--format", "json", "--full"],
                         capture_output=True, text=True, check=True).stdout
    return [l for l in map(json.loads, out.splitlines()) if l["kind"] not in ("outcome", "stop")]


# Shorter than the event log, told or whole; far shorter for the nodes' runs. Which seed fails
# first depends on the host, so these hold for every failing seed: a race in jobs can show
# after a few hundred events, and its whole story is then a third of them.
told = len(full())
far = case in ("nodes", "partition")
assert len(lines) * (10 if far else 4) < len(records), (len(lines), len(records))
assert told * (4 if far else 1) < len(records), (told, len(records))
# The stop event is a record of the run, the same in `log events --from N --to N`.
at = subprocess.run([patina, "log", "events", run, "--from", str(stop["seq"]), "--to", str(stop["seq"])],
                    capture_output=True, text=True, check=True).stdout.splitlines()
ev = json.loads(at[-1])
assert ev.get("seq") == stop["seq"], (ev, stop)
assert any(l["seq"] == stop["seq"] and l["text"] == stop["text"] for l in lines), "the stop line is not shown"

if case == "thread":
    # The thread that exited with the run's status wrote the stop event to stderr.
    end = [e for e in records if e["type"] == "call" and e["name"] == "exit_group" and e["args"][0] == result["guest"]["exit"]]
    assert end, "no exit_group with the run's status"
    assert ev["type"] == "call" and ev["args"][0] == 2 and ev["slot"] == end[-1]["slot"], ev
elif case == "crash":
    # The last crash that lost something (an earlier one may have lost nothing).
    crash = [e for e in records if e["type"] == "crash" and e["lost"]["paths"]][-1]
    near = [l for l in lines if l["kind"] in ("crash", "unsynced") and l["seq"] == crash["seq"]]
    assert any(p in l["text"] for l in near for p in crash["lost"]["paths"]), near
    assert ev["type"] == "sdk" and ev["op"] == "assert", ev
    assert result["message"].startswith(ev["label"]), (ev, result["message"])
elif case in ("nodes", "partition"):
    nodes = header["nodes"]
    # The stop is a message into the driver, sent by the node the event is of.
    assert stop.get("to") == "driver" and ev.get("node") == stop["who"], (stop, ev)
    # Every node's messages are in the story.
    talk = {l["who"] for l in full() if l["kind"] == "msg"}
    assert set(nodes) <= talk, (nodes, talk)
    if case == "partition":
        # A partition of the seed came before the stop, and the last one is in the story.
        # (Which node it cut off depends on the seed: the sender, or the others.)
        cuts = [e for e in records if e["type"] == "net" and e.get("event") == "cut" and e.get("by") == "seed"
                and e["seq"] < stop["seq"]]
        assert cuts, stop
        assert any(l["kind"] == "network" and l["seq"] == cuts[-1]["seq"] for l in story), cuts[-1]
else:
    sys.exit(f"unknown case {case}")
print(f"{case}: {len(lines)} lines told ({told} whole) for {len(records)} events; stop at event "
      f"{stop['seq']}: {stop['who']} {stop['text'][:60]}")
