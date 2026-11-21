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

# A sweep's runs are its seeds' runs: untold, each restarts once at the mark, the same digests as
# the single runs at any width; its summary names the flag once. Told, no run restarts.
single = {s: run(f"02/setup-{s}", s, EXTRA, "setup", flags=flags) for s in range(1, 7)}
if not all(restarted(x) and held(x) and "--faults-held" in x.printed for x in single.values()):
    die("an untold run of a program that marks: not every one restarted, held, with the flag named")


def sweep(j, more=()):
    out = os.path.join(RUNS, f"02/setup-sweep-j{j}{''.join(more)}")
    subprocess.run(["rm", "-rf", out], check=True)
    p = subprocess.run([PATINA, "sweep", "--seeds", "1..6", "-j", j, "--keep", "all", "--out", out,
                        "--mount", GUESTS + ":/guest:copy", *flags, *more, "--", *EXTRA, "setup"],
                       capture_output=True, text=True, timeout=300)
    runs = {int(d.removeprefix("seed-")): Run(os.path.join(out, d)) for d in os.listdir(out) if d.startswith("seed-")}
    if len(runs) != 6:
        die(f"sweep -j {j}: exit {p.returncode}: {sorted(runs)} {p.stderr[-300:]}")
    return runs, p.stdout


for j in ["1", "8"]:
    runs, printed = sweep(j)
    if {s: x.outcome["digest"] for s, x in runs.items()} != {s: x.outcome["digest"] for s, x in single.items()}:
        die(f"sweep -j {j}: digests differ from the single runs'")
    if not all(restarted(x) for x in runs.values()) or printed.count("--faults-held") != 1:
        die(f"sweep -j {j}: restarted {[s for s, x in runs.items() if restarted(x)]}, flag named {printed.count('--faults-held')} times")
runs, printed = sweep("8", ["--faults-held"])
if any(restarted(x) for x in runs.values()):
    die(f"a told sweep: restarted {[s for s, x in runs.items() if restarted(x)]}")
if {s: x.outcome["digest"] for s, x in runs.items()} != {s: x.outcome["digest"] for s, x in single.items()}:
    die("a told sweep: digests differ from the untold runs'")
print("a sweep's runs are its seeds' single runs, digest for digest at -j 1 and -j 8; told, none restarts")

out = os.path.join(RUNS, "02/verify")
# lint-allow: seed — the guest's `fail` mode violates its assertion on every seed
p = subprocess.run([PATINA, "verify", "--seed", "1", "--runs", "2", "--out", out, "--mount", GUESTS + ":/guest:copy",
                    "--", *C, "fail"], capture_output=True, text=True, timeout=120)
# Identical runs: verify ends with the runs' own outcome and its exit status.
if p.returncode != 1 or "identical" not in p.stdout or "violation" not in p.stdout:
    die(f"verify of a violation: exit {p.returncode}: {p.stdout} {p.stderr}")
print("a violation repeats identically")
