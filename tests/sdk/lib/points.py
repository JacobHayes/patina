import json
import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sdk import GUESTS, PATINA, RUNS, Run, die, report, run  # noqa: E402

C = ["/guest/sdk-c"]
EXTRA = ["/guest/sdk-extra"]


def bits(r):
    return r.stdout.split()[0].removeprefix("a=")


# A named point fires alone, without the buggify class; points not named stay quiet; with no
# buggify setting at all nothing fires.
alone = run("02/alone", 7, C, "script", "two", flags=["--fault", "buggify:point-a=1000"])
if bits(alone) != "1" * 20 or alone.site("point-a")["held"] != 20:
    die(f"a named point alone: {alone.stdout!r} {alone.site('point-a')}")
if alone.site("point-b")["held"] != 0:
    die(f"a point not named: {alone.site('point-b')}")
off = run("02/off", 7, C, "script", "two")
if bits(off) != "0" * 20 or off.site("point-a")["held"] != 0 or off.site("point-b")["held"] != 0:
    die(f"no buggify setting: {off.stdout!r} {off.site('point-a')}")

on = ["--fault", "buggify:point-a=500"]
a = run("02/a", 7, C, "script", flags=on)
b = run("02/b", 7, C, "script", flags=on)
two = run("02/two", 7, C, "script", "two", flags=on + ["--fault", "buggify:point-b=500"])
if bits(a) != bits(b) or a.outcome["digest"] != b.outcome["digest"]:
    die(f"one seed, two decisions: {bits(a)} {bits(b)}")
if set(bits(a)) != {"0", "1"}:
    die(f"point-a at 500 per mille over 20 calls: {bits(a)}")
if bits(two) != bits(a) or two.site("point-b")["evaluated"] != 20:
    die(f"a second point moved the first one's decisions: {bits(a)} -> {bits(two)}")
other = run("02/other", 8, C, "script", flags=on)
if bits(other) == bits(a):
    die(f"seeds 7 and 8 decide alike: {bits(a)}")
print(f"point-a seed 7: {bits(a)} (with point-b too: {bits(two)}); seed 8: {bits(other)}")

for p, want in [("1000", "1" * 20), ("0", "0" * 20)]:
    r = run(f"02/point-{p}", 7, C, "script", flags=["--fault", f"buggify:point-a={p}"])
    if bits(r) != want or r.site("point-a")["held"] != want.count("1"):
        die(f"buggify:point-a={p}: {bits(r)} {r.site('point-a')}")
print("buggify:point-a=1000 fires 20 of 20, =0 none")

# A coin: held on some seeds, not on others. Seeds from 1 until both are seen (at most 64: a
# search, not a rate).
held = {}
for s in range(1, 65):
    held[s] = run(f"02/coin-{s}", s, C, "coin").site("coin")["held"]
    if any(held.values()) and not all(held.values()):
        break
else:
    die(f"coin over seeds 1-64: held on {[s for s, h in held.items() if h]}")
print(f"sometimes(coin) held on seeds {[s for s, h in held.items() if h]} of 1-{s}")

r = run("02/fork", 1, EXTRA, "fork")
for label in ["forked-child", "exec-child", "parent-done"]:
    if r.site(label)["held"] != 1:
        die(f"fork: {label} {r.site(label)}")
print("a forked and an exec'd child report into the run's table")

# A program that marks setup-complete gets faults only after the mark: a run not told so meets
# the mark with faults acting, starts again held and says so; one told (--faults-held) starts
# held, and is the same run. One that never marks gets them from the start, in one pass.
def held(r):
    return json.load(open(os.path.join(r.out, "run.json")))["config"].get("faults-held") is True


def restarted(r):
    return r.outcome["faults"]["window"].get("restarted") is True


flags = ["--fault", "buggify:setup-point=1000"]
r = run("02/setup", 1, EXTRA, "setup", flags=flags)
if r.stdout != "before=00000 after=11111\n" or not r.sdk["setup_complete"]:
    die(f"faults held until setup-complete: {r.stdout!r} {r.sdk['setup_complete']}")
if not held(r) or not restarted(r):
    die(f"a run not told that meets the mark: held {held(r)}, restarted {restarted(r)}")
told = run("02/setup-told", 1, EXTRA, "setup", flags=flags + ["--faults-held"])
if not held(told) or restarted(told) or told.outcome["digest"] != r.outcome["digest"]:
    die(f"a told run: held {held(told)}, restarted {restarted(told)}, digest {told.outcome['digest']} vs {r.outcome['digest']}")
if held(alone) or restarted(alone) or alone.outcome["faults"]["window"]["from_seq"] != 0:
    die(f"a program that never marks setup-complete: held {held(alone)}, window {alone.outcome['faults']['window']}")
print("faults held until setup-complete: quiet before the mark, firing after, the first run restarted once; never marked: from the start")

# The rerun line of a held run (its finding: a checker that always fails) reproduces it exactly,
# held from the start.
judged = run("02/setup-judged", 1, EXTRA, "setup", flags=flags + ["--check", "false"])
rep = report(judged)
line = shlex.split(rep["groups"][0]["rerun"])
again = os.path.join(RUNS, "02/setup-rerun")
subprocess.run(["rm", "-rf", again], check=True)
subprocess.run([PATINA, "run", "--out", again, *line[2:]], capture_output=True, text=True, timeout=120)
again = Run(again)
if again.outcome["digest"] != judged.outcome["digest"] or not held(again) or restarted(again):
    die(f"the rerun line {line}: digest {again.outcome['digest']} vs {judged.outcome['digest']}, restarted {restarted(again)}")
print("the rerun line of a held run is the run, held from the start")

# A sweep learns it from the first runs that meet the mark: runs it starts after one of them ended
# start held, so only its first batch (-j 2) restarts; every run is held, and sweep.json keeps it
# for a resumed sweep, whose new runs start held.
sw = os.path.join(RUNS, "02/setup-sweep")


def sweep(seeds):
    p = subprocess.run([PATINA, "sweep", "--seeds", seeds, "-j", "2", "--keep", "all", "--out", sw,
                        "--mount", GUESTS + ":/guest:copy", *flags, "--", *EXTRA, "setup"],
                       capture_output=True, text=True, timeout=300)
    runs = {int(d.removeprefix("seed-")): Run(os.path.join(sw, d)) for d in os.listdir(sw) if d.startswith("seed-")}
    if len(runs) != int(seeds.split("..")[1]) or not all(held(x) for x in runs.values()):
        die(f"sweep {seeds}: exit {p.returncode}: held {[s for s, x in runs.items() if held(x)]} {p.stderr[-300:]}")
    return {s for s, x in runs.items() if restarted(x)}


subprocess.run(["rm", "-rf", sw], check=True)
first = sweep("1..6")
if not first or not first <= {1, 2} or json.load(open(os.path.join(sw, "sweep.json"))).get("faults_held_from") not in (2, 3):
    die(f"a sweep of a program that marks: restarted {sorted(first)} (at most its first batch, 1-2)")
if sweep("1..8") != first:
    die("a resumed sweep restarted a new run")
print(f"a sweep restarts only its first batch ({sorted(first)} of 1-6), and a resumed one none")

# Which runs of a sweep are told follows seed order, not which run finished first: a setup that
# fails where a fault point fires leaves the seeds below the first that meets the mark unheld,
# and the seeds above it held, whatever the sweep's width, and when it is stopped and resumed.
# The sweep starts at a seed whose setup fails (searched for); 30 seeds of a point at 500 per
# mille all failing is a 1e-9 chance.
fail = ["--fault", "buggify:setup-fail=500"]
s0 = next((s for s in range(1, 65) if run("02/setup-fail", s, EXTRA, "setup-fail", flags=fail).cls == "failure"), None)
if s0 is None:
    die("setup-fail: no seed of 1-64 failed its setup")
widths = {}
# "stop": a sweep stopped at its first finding (-j 4), then resumed: the same runs as one sweep.
for j in ["1", "4", "stop"]:
    out = os.path.join(RUNS, f"02/setup-fail-j{j}")
    subprocess.run(["rm", "-rf", out], check=True)
    for more in [["--max-findings", "1"], []] if j == "stop" else [[]]:
        subprocess.run([PATINA, "sweep", "--seeds", f"{s0}..{s0 + 29}", "-j", "4" if j == "stop" else j, *more,
                        "--out", out, "--mount", GUESTS + ":/guest:copy", *fail, "--", *EXTRA, "setup-fail"],
                       capture_output=True, text=True, timeout=300)
    got = {}
    for d in os.listdir(out):
        if d.startswith("seed-"):
            res = json.load(open(os.path.join(out, d, "result.json")))
            cfg = json.load(open(os.path.join(out, d, "run.json")))["config"]
            got[int(d.removeprefix("seed-"))] = (cfg.get("faults-held") is True, res["digest"], res["outcome"])
    widths[j] = got
told = sorted(s for s, x in widths["1"].items() if x[0])
if len(widths["1"]) != 30 or not told or widths["1"][s0][0]:
    die(f"setup-fail sweep from seed {s0}: told {told}")
for j in ["4", "stop"]:
    if widths[j] != widths["1"]:
        die(f"setup-fail sweeps from seed {s0}: {j} differs from -j 1 at {[s for s in widths['1'] if widths[j].get(s) != widths['1'][s]]}")
if any(widths["1"][s][0] for s in range(s0, told[0])) or not all(widths["1"][s][0] for s in range(told[0], s0 + 30)):
    die(f"setup-fail: told {told}: not every seed from the first that met the mark")
print(f"held from seed {told[0]} of {s0}-{s0 + 29}, the same at -j 1, -j 4, and stopped and resumed")

out = os.path.join(RUNS, "02/verify")
# lint-allow: seed — the guest's `fail` mode violates its assertion on every seed
p = subprocess.run([PATINA, "verify", "--seed", "1", "--runs", "2", "--out", out, "--mount", GUESTS + ":/guest:copy",
                    "--", *C, "fail"], capture_output=True, text=True, timeout=120)
# Identical runs: verify ends with the runs' own outcome and its exit status.
if p.returncode != 1 or "identical" not in p.stdout or "violation" not in p.stdout:
    die(f"verify of a violation: exit {p.returncode}: {p.stdout} {p.stderr}")
print("a violation repeats identically")
