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

# A program that is its own harness: main's `ready` probe waits for a file the program creates
# at the end of its setup; no fault point fires before the probe passes, all do after.
CONF = os.path.join(RUNS, "02/ready.toml")
os.makedirs(os.path.dirname(CONF), exist_ok=True)
with open(CONF, "w") as f:
    f.write('[machine.main]\nready = "test -e /tmp/setup-done"\n')
flags = ["--config", CONF, "--fault", "buggify:ready-point=1000"]
r = run("02/ready", 1, EXTRA, "ready", flags=flags)
if r.cls != "ok" or r.stdout != "before=00000 after=11111\n":
    die(f"faults after main's probe passed: {r.cls} {r.stdout!r}")
print("main's ready probe: quiet before it passes, firing after")

# The rerun line of a run with a probe (its finding: a checker that always fails) reproduces it
# exactly.
judged = run("02/ready-judged", 1, EXTRA, "ready", flags=flags + ["--check", "false"])
rep = report(judged)
line = shlex.split(rep["groups"][0]["rerun"])
again = os.path.join(RUNS, "02/ready-rerun")
subprocess.run(["rm", "-rf", again], check=True)
subprocess.run([PATINA, "run", "--out", again, *line[2:]], capture_output=True, text=True, timeout=120)
again = Run(again)
if again.outcome["digest"] != judged.outcome["digest"]:
    die(f"the rerun line {line}: digest {again.outcome['digest']} vs {judged.outcome['digest']}")
print("the rerun line of a run with a ready probe is the run")

# A sweep's runs are its seeds' runs, the same digests as the single runs at any width.
single = {s: run(f"02/ready-{s}", s, EXTRA, "ready", flags=flags) for s in range(1, 7)}


def sweep(j):
    out = os.path.join(RUNS, f"02/ready-sweep-j{j}")
    subprocess.run(["rm", "-rf", out], check=True)
    p = subprocess.run([PATINA, "sweep", "--seeds", "1..6", "-j", j, "--keep", "all", "--out", out,
                        "--mount", GUESTS + ":/guest:copy", *flags, "--", *EXTRA, "ready"],
                       capture_output=True, text=True, timeout=300)
    runs = {int(d.removeprefix("seed-")): Run(os.path.join(out, d)) for d in os.listdir(out) if d.startswith("seed-")}
    if len(runs) != 6:
        die(f"sweep -j {j}: exit {p.returncode}: {sorted(runs)} {p.stderr[-300:]}")
    return runs


for j in ["1", "8"]:
    runs = sweep(j)
    if {s: x.outcome["digest"] for s, x in runs.items()} != {s: x.outcome["digest"] for s, x in single.items()}:
        die(f"sweep -j {j}: digests differ from the single runs'")
print("a sweep's runs are its seeds' single runs, digest for digest at -j 1 and -j 8")

out = os.path.join(RUNS, "02/verify")
# lint-allow: seed — the guest's `fail` mode violates its assertion on every seed
p = subprocess.run([PATINA, "verify", "--seed", "1", "--runs", "2", "--out", out, "--mount", GUESTS + ":/guest:copy",
                    "--", *C, "fail"], capture_output=True, text=True, timeout=120)
# Identical runs: verify ends with the runs' own outcome and its exit status.
if p.returncode != 1 or "identical" not in p.stdout or "violation" not in p.stdout:
    die(f"verify of a violation: exit {p.returncode}: {p.stdout} {p.stderr}")
print("a violation repeats identically")
