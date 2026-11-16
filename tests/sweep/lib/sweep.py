"""tests/sweep/01-sweep.sh. Environment from ./check: PATINA, PATINA_GUESTS, RUNS."""
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

PATINA = os.environ["PATINA"]
GUEST = os.path.join(os.environ["PATINA_GUESTS"], "sweep-bugs")
RUNS = os.environ["RUNS"]
HERE = os.path.dirname(os.path.abspath(__file__))
FS = ["--fault", "fs-error-permille=30"]


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def patina(*args, timeout=60):
    p = subprocess.run([PATINA, *args], capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def sweep(name, *args):
    """`patina sweep --out RUNS/name ARGS`: (exit status, report.json, text output, both
    streams)."""
    out = os.path.join(RUNS, name)
    st, so, se = patina("sweep", "-j", "4", "--out", out, *args)
    so = so + se
    try:
        with open(os.path.join(out, "report.json")) as f:
            rep = json.load(f)
    except OSError:
        die(f"sweep {name}: no report.json (exit {st}): {se[-2000:]}")
    return st, rep, so


def report(*args):
    st, so, se = patina("report", "--format", "json", *args)
    if not so:
        die(f"report {args}: {se}")
    return st, json.loads(so)


def result(d):
    with open(os.path.join(d, "result.json")) as f:
        return json.load(f)


def findings(rep):
    return [g for g in rep["groups"] if g["outcome"] in ("violation", "liveness", "failure", "crash")]


# Two bugs over 30 seeds: two findings, each with a first seed that replays identically.
st, rep, text = sweep("two", "--seeds", "1..30", *FS, "--", GUEST, "race", "fserr")
f = findings(rep)
if st != 1 or len(f) != 2 or len(rep["groups"]) != 2:
    die(f"two bugs: exit {st}, groups {[(g['signature'], g['count']) for g in rep['groups']]}\n{text}")
if sum(g["count"] for g in f) != rep["findings"] or min(g["count"] for g in f) < 2:
    die(f"two bugs: each bug should be one group of several seeds: {[(g['signature'], g['seeds']) for g in f]}")
for g in f:
    if (g["replay"] or {}).get("result") != "identical":
        die(f"{g['signature']}: replay {g['replay']}")
fs = [g for g in f if g["outcome"] == "failure"]
if len(fs) != 1 or "fs-error" not in fs[0]["faults"]["every"]:
    die(f"the fs-error finding names no fault in every failing run: {fs}")
# The fs-error bug prints a byte count that varies by seed: its runs still form one group.
if fs[0]["count"] < 2:
    die(f"the fs-error bug did not collapse across seeds: {fs}")
# The `new:` lines name each group's first (lowest) seed, as the report does.
for g in f:
    if f"seed {g['first']['seed']}:" not in text:
        die(f"{g['signature']}: the report's first seed {g['first']['seed']} is not the one announced\n{text}")
print(f"two bugs, {rep['findings']} failing seeds of 30 -> 2 groups:")
for g in f:
    print(f"  {g['signature']}  seeds {g['count']}, first {g['first']['seed']}, replay {g['replay']['result']}, faults in every run: {g['faults']['every']}")

# A replay of a sweep's run is not one of the sweep's runs: the report and a resumed sweep
# count the same runs as before.
patina("replay", g["first"]["dir"])
st, again = report(os.path.join(RUNS, "two"))
if again["runs"] != rep["runs"]:
    die(f"after a replay of {g['first']['dir']}: report counts {again['runs']} runs, the sweep {rep['runs']}")

# A sweep directory holds one sweep: the same command resumes it, a changed argument or a
# rebuilt program replaces it.
prog = os.path.join(RUNS, "stale-prog")
shutil.copyfile(GUEST, prog)
os.chmod(prog, 0o755)
st, rep, _ = sweep("stale", "--seeds", "1..6", *FS, "--", prog, "fserr")
first = result(os.path.join(RUNS, "stale", "seed-1"))
st, rep2, _ = sweep("stale", "--seeds", "1..8", *FS, "--", prog, "fserr")
if result(os.path.join(RUNS, "stale", "seed-1")) != first or rep2["runs"] != 8:
    die(f"the same sweep with two more seeds did not resume: {rep2['runs']} runs")
st, rep3, _ = sweep("stale", "--seeds", "1..8", *FS, "--", prog)
if rep3["findings"] or rep3["runs"] != 8:
    die(f"a changed argument reused the old runs: {rep3['findings']} findings, {rep3['runs']} runs")
with open(prog, "ab") as fh:
    fh.write(b"\0")
st, rep4, _ = sweep("stale", "--seeds", "1..8", *FS, "--", prog)
want = subprocess.run(["sha256sum", prog], capture_output=True, text=True).stdout.split()[0]
if json.load(open(os.path.join(RUNS, "stale", "seed-1", "run.json")))["program"]["sha256"] != want:
    die("a rebuilt program reused the old runs")
print("a replay leaves the sweep's run count alone; the same sweep resumes, a changed argument or program replaces it")

# A seed run alone equals the same seed inside the sweep, at any width.
digests = lambda name: {s: result(os.path.join(RUNS, name, f"seed-{s}"))["digest"] for s in range(1, 31)}
patina("sweep", "-j", "1", "--out", os.path.join(RUNS, "two-j1"), "--seeds", "1..30", *FS, "--", GUEST, "race", "fserr")
if digests("two") != digests("two-j1"):
    die("seeds 1-30 at -j 4 and -j 1 differ")
for g in f:
    s = g["first"]["seed"]
    alone = os.path.join(RUNS, f"alone-{s}")
    patina("run", "--seed", str(s), "--out", alone, *FS, "--", GUEST, "race", "fserr")
    a, b = result(alone), result(g["first"]["dir"])
    if (a["digest"], a["signature"]) != (b["digest"], b["signature"]):
        die(f"seed {s}: alone {a['digest']} {a['signature']}, in the sweep {b['digest']} {b['signature']}")
print("first seeds run alone: same digest and signature as inside the sweep")

# The bug-free guest: exit 0. A `sometimes` that never holds: vacuous (exit 2) unless allowed.
st, rep, _ = sweep("clean", "--seeds", "1..8", *FS, "--", GUEST)
if st != 0 or rep["groups"] or rep["vacuous"]:
    die(f"bug-free guest: exit {st} {rep['groups']}")
st, rep, text = sweep("never", "--seeds", "1..4", "--", GUEST, "never")
if st != 2 or rep["sdk"]["sometimes_never_held"] != ["rare-state"]:
    die(f"a sometimes that never holds: exit {st} {rep['sdk']}\n{text}")
st, _ = report("--allow-unmet", "rare-state", os.path.join(RUNS, "never"))
cfg = os.path.join(RUNS, "allow.toml")
with open(cfg, "w") as fh:
    fh.write('[sdk]\nallow-unmet = ["rare-state"]\n')
st2, _, _ = sweep("never-allowed", "--seeds", "1..4", "--config", cfg, "--", GUEST, "never")
if (st, st2) != (0, 0):
    die(f"allow-unmet: report exit {st}, sweep with [sdk] allow-unmet exit {st2}")
print("bug-free: exit 0; unmet sometimes: exit 2, allowed (flag or config): exit 0")

# A fault class with nothing to act on makes the result vacuous, named: the net preset on a
# guest without sockets.
st, rep, _ = sweep("net", "--seeds", "1..4", "--faults", "net", "--", GUEST)
if st != 2 or not rep["faults"]["eligible_zero"] or not all(c.startswith("net-") for c in rep["faults"]["eligible_zero"]):
    die(f"--faults net without sockets: exit {st} {rep['faults']}")
print(f"--faults net without sockets: exit 2, eligible 0: {rep['faults']['eligible_zero']}")

# Cases: three cases by four seeds is twelve runs, grouped by case; `report` over twelve
# separate `patina run` directories gives the same groups.
cases = os.path.join(RUNS, "cases.txt")
with open(cases, "w") as fh:
    fh.write("race\nfserr\nclean\n")
st, rep, text = sweep("cases", "--seeds", "1..4", "--cases", cases, *FS, "--", GUEST, "{}")
if rep["runs"] != 12:
    die(f"--cases: {rep['runs']} runs")
for g in rep["groups"]:
    if g["case"] not in ("race", "fserr"):
        die(f"--cases: group {g['signature']} has case {g['case']}")
for s in range(1, 5):
    for c in ("race", "fserr", "clean"):
        patina("run", "--seed", str(s), "--out", os.path.join(RUNS, "separate", f"seed-{s}", c), *FS, "--", GUEST, c)
_, sep = report(os.path.join(RUNS, "separate"))
key = lambda rep: sorted((g["signature"], g["case"], g["seeds"]) for g in rep["groups"])
if key(sep) != key(rep):
    die(f"report over separate runs: {key(sep)}\nthe sweep: {key(rep)}")
print(f"--cases: 12 runs, groups by case {[(g['case'], g['count']) for g in rep['groups']]}; report over 12 separate runs agrees")

# A host file that changes between the run and its replay: nondeterministic, not a finding.
# Without the change (red/green), the same failure is a finding that replays identically.
host = os.path.join(RUNS, "host")
os.makedirs(host)
val = os.path.join(host, "val")
stop = threading.Event()


def churn():
    n = 0
    while not stop.is_set():
        n += 1
        with open(val + ".t", "w") as fh:
            fh.write(str(n))
        os.rename(val + ".t", val)
        time.sleep(0.001)


with open(val, "w") as fh:
    fh.write("0")
st, rep, _ = sweep("steady", "--seeds", "1", "--mount", f"{host}:/h", "--", GUEST, "cat", "/h/val")
if st != 1 or rep["groups"][0]["replay"]["result"] != "identical":
    die(f"steady host file: exit {st} {rep['groups']}")
t = threading.Thread(target=churn)
t.start()
try:
    st, rep, _ = sweep("churn", "--seeds", "1", "--mount", f"{host}:/h", "--", GUEST, "cat", "/h/val")
finally:
    stop.set()
    t.join()
g = rep["groups"][0]
if st != 2 or g["outcome"] != "nondeterministic" or findings(rep):
    die(f"changing host file: exit {st} {rep['groups']}")
print(f"host file changing under the replay: {g['outcome']} ({g['replay']['message'][:80]}); steady: finding, identical")

# Interrupted: the running children end, every remaining directory holds a finished run,
# and the report covers them.
out = os.path.join(RUNS, "interrupted")
p = subprocess.Popen([PATINA, "sweep", "-j", "4", "--seeds", "1..400", "--out", out, "--",
                      "/bin/sh", "-c", "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(1.5)
p.send_signal(signal.SIGINT)
so, se = p.communicate(timeout=30)
left = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "..", "leftovers.py"), out],
                      capture_output=True, text=True)
partial = [d for d in os.listdir(out) if d.startswith("seed-") and not os.path.exists(os.path.join(out, d, "result.json"))]
if p.returncode != 2 or left.returncode != 0 or partial or not os.path.exists(os.path.join(out, "report.json")):
    die(f"interrupted: exit {p.returncode}, leftovers {left.stdout!r}, partial {partial}\n{se[-1000:]}")
done = len([d for d in os.listdir(out) if d.startswith("seed-")])
print(f"interrupted after 1.5 s: {done} runs finished and reported, none partial, no process left")

# Minimize: a finding under --faults all (file errors raised to 40 per mille) keeps only the
# file-error setting.
st, rep, _ = sweep("many-faults", "--seeds", "1..20", "--max-findings", "1",
                   "--faults", "all", "--fault", "fs-error-permille=40", "--", GUEST, "fserr")
f = findings(rep)
if st != 1 or len(f) != 1 or rep["runs"] >= 20:
    die(f"--max-findings 1: exit {st}, {rep['runs']} runs, {[g['signature'] for g in f]}")
st, so, se = patina("minimize", "--format", "json", f[0]["first"]["dir"], timeout=120)
m = json.loads(so or "{}")
if st != 0 or not m.get("reduced") or m["runs"] > 30 or len(m["tries"]) != m["runs"] or not m["to"].startswith("fs-error-permille=") or " " in m["to"]:
    die(f"minimize: exit {st} {m} {se[-1000:]}")
if result(m["dir"])["signature"] != f[0]["signature"]:
    die(f"minimize: the written run's signature differs from {f[0]['signature']}")
# The rerun command it ends with reproduces the reduced run.
rerun = m["rerun"].split()
if rerun[:2] != ["patina", "run"] or "--out" in rerun:
    die(f"minimize: rerun {m['rerun']}")
r = subprocess.run(["sh", "-c", m["rerun"].replace("patina run", f"'{PATINA}' run --format json --out '{RUNS}/min-rerun'", 1)], capture_output=True, text=True, timeout=60)
if result(os.path.join(RUNS, "min-rerun"))["digest"] != result(m["dir"])["digest"]:
    die(f"minimize: its rerun command does not reproduce the reduced run: {m['rerun']}")
print(f"--max-findings 1 stopped after {rep['runs']} runs; minimize in {m['runs']} runs: {m['from']} -> {m['to']}; its rerun reproduces it")
