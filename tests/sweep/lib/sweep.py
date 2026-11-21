"""tests/sweep/01-sweep.sh. Environment from ./check: PATINA, PATINA_GUESTS, RUNS."""
import json
import os
import shutil
import signal
import subprocess
import sys
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


def cfg(*keys):
    """A patina.toml holding these KEY=VALUE settings (tests/cfg): its path."""
    return subprocess.run([os.environ["PATINA_CFG"], *keys], capture_output=True, text=True, check=True).stdout.strip()


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
# Its example is the first run's line as written, with its own count.
first_err = open(os.path.join(RUNS, "two", f"seed-{fs[0]['first']['seed']}", "inc-0", "stderr")).read().strip().splitlines()[-1]
if fs[0].get("example") != first_err or not any(c.isdigit() for c in first_err):
    die(f"the fs-error group's example {fs[0].get('example')!r}, its first run wrote {first_err!r}")
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
# No --seeds: seeds 1 to 100.
st, rep, _ = sweep("default-seeds", "--", GUEST)
seeds = sorted(int(d[len("seed-"):]) for d in os.listdir(os.path.join(RUNS, "default-seeds")) if d.startswith("seed-"))
if st != 0 or rep["runs"] != 100 or seeds != list(range(1, 101)):
    die(f"sweep without --seeds: exit {st}, {rep['runs']} runs, seeds {seeds[:3]}..{seeds[-3:]}")
st, rep, text = sweep("never", "--seeds", "1..4", "--", GUEST, "never")
if st != 2 or rep["sdk"]["sometimes_never_held"] != ["rare-state"]:
    die(f"a sometimes that never holds: exit {st} {rep['sdk']}\n{text}")
st, _ = report("--allow-unmet", "rare-state", os.path.join(RUNS, "never"))
allow = os.path.join(RUNS, "allow.toml")
with open(allow, "w") as fh:
    fh.write('[sdk]\nallow-unmet = ["rare-state"]\n')
st2, _, _ = sweep("never-allowed", "--seeds", "1..4", "--config", allow, "--", GUEST, "never")
if (st, st2) != (0, 0):
    die(f"allow-unmet: report exit {st}, sweep with [sdk] allow-unmet exit {st2}")
print("bug-free: exit 0; unmet sometimes: exit 2, allowed (flag or config): exit 0")

# A fault class with nothing to act on makes the result vacuous, named: the net preset on a
# guest without sockets. On a TCP-only guest the preset's datagram classes are not applicable
# (exit 0); the same class named with --fault is vacuous.
st, rep, _ = sweep("net", "--seeds", "1..4", "--faults", "net", "--", GUEST)
if st != 2 or not rep["faults"]["eligible_zero"] or not all(c.startswith("net-") for c in rep["faults"]["eligible_zero"]):
    die(f"--faults net without sockets: exit {st} {rep['faults']}")
TCP = [os.path.join(os.environ["PATINA_GUESTS"], "sockets"), "chunk", "correct"]
calm = ["--fault", "net-reset-permille=0", "--fault", "net-connect-refuse-permille=0"]
st2, rep2, _ = sweep("net-tcp", "--seeds", "1..2", "--faults", "net", *calm, "--", *TCP)
st3, rep3, _ = sweep("net-tcp-drop", "--seeds", "1..2", "--faults", "net", *calm, "--fault", "net-drop-permille=9", "--", *TCP)
if (st2, rep2["faults"]["not_applicable"], st3, rep3["faults"]["eligible_zero"]) != (0, ["net-drop", "net-dup", "net-reorder"], 2, ["net-drop"]):
    die(f"--faults net on TCP only: exit {st2} {rep2['faults']}; net-drop named: exit {st3} {rep3['faults']}")
print(f"--faults net: without sockets exit 2, eligible 0: {rep['faults']['eligible_zero']}; TCP only: exit 0, not applicable: {rep2['faults']['not_applicable']}; net-drop named: exit 2")

# --ok-exit N:CLASS: exit 3 is a clean failure only in runs where fs-error injected; under
# another class's condition it is a finding. The same from patina.toml, with [sweep] known.
# Known findings and runs --ok-exit allowed are counted apart from findings.
okx = ["--seeds", "1..12", *FS, "--", GUEST, "fserr"]
st, rep, _ = sweep("okx", "--ok-exit", "3:fs-error", *okx)
st2, rep2, _ = sweep("okx-other", "--ok-exit", "3:mem-error", *okx)
if (st, rep["findings"], st2) != (0, 0, 1) or rep.get("ok_exit", 0) < 1 or rep2["findings"] != rep["ok_exit"]:
    die(f"--ok-exit 3:fs-error: exit {st} {rep['outcomes']}; 3:mem-error: exit {st2} {rep2['outcomes']}")
rr = rep2["groups"][0]["rerun"]
if "--ok-exit 3:mem-error" not in rr:
    die(f"--ok-exit with a condition: the rerun line {rr}")
kf = os.path.join(RUNS, "okx-known.txt")
with open(kf, "w") as fh:
    fh.write("noted failure exit:*\nnear failure exit: *exit N\n")
okx_toml = os.path.join(RUNS, "okx.toml")
with open(okx_toml, "w") as fh:
    fh.write(f'[run]\nok-exit = ["3:mem-error"]\n[sweep]\nknown = "okx-known.txt"\n')
st3, rep3, text3 = sweep("okx-toml", "--config", okx_toml, *okx)
head = text3.split("patina sweep: ", 1)[-1].split("\n", 1)[0]
near = [e.get("near") for e in rep3["known"]["entries"]]
if st3 != 0 or rep3["known"]["findings"] != rep2["findings"] or " 0 findings" not in f" {head}" or near != [None, rep2["groups"][0]["signature"]]:
    die(f"[run] ok-exit and [sweep] known: exit {st3}, {head!r}, known {rep3['known']}")
print(f"--ok-exit 3:fs-error: {rep['ok_exit']} of 12 ok by it; 3:mem-error: {rep2['findings']} findings, as is the rerun line; from patina.toml with [sweep] known: {head}")

# An --out directory of an older patina is replaced; one with no patina output is refused.
old = os.path.join(RUNS, "old-layout")
os.makedirs(os.path.join(old, "failures"))
open(os.path.join(old, "campaign-state.json"), "w").close()
st, rep, text = sweep("old-layout", "--seeds", "1..2", "--", GUEST)
if st != 0 or os.path.exists(os.path.join(old, "failures")):
    die(f"an 0.5 campaign directory: exit {st}\n{text}")
mine = os.path.join(RUNS, "not-patina")
os.makedirs(mine)
open(os.path.join(mine, "notes.txt"), "w").close()
st, so, se = patina("sweep", "--seeds", "1", "--out", mine, "--", GUEST)
if st != 2 or os.listdir(mine) != ["notes.txt"]:
    die(f"a directory with no patina output: exit {st}, {os.listdir(mine)}: {se}")
# A run.json among files of the user's is not enough to make a directory patina's; a run's
# own directory is replaced.
open(os.path.join(mine, "run.json"), "w").close()
st, so, se = patina("sweep", "--seeds", "1", "--out", mine, "--", GUEST)
if st != 2 or sorted(os.listdir(mine)) != ["notes.txt", "run.json"]:
    die(f"a directory with a run.json and a file of the user's: exit {st}, {os.listdir(mine)}: {se}")
one = os.path.join(RUNS, "one-run")
if patina("run", "--seed", "1", "--out", one, "--", GUEST)[0] != 0:
    die("patina run for the one-run directory")
st, rep, text = sweep("one-run", "--seeds", "1..2", "--", GUEST)
if st != 0 or os.path.exists(os.path.join(one, "inc-0")):
    die(f"a run's directory as --out: exit {st}\n{text}")
print("an older patina's --out directory and a run's are replaced; one holding files patina does not write is refused, untouched")

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

# Whole-command cases: each line its own program and arguments (two programs here), in a
# directory with a short name; the report names the whole case and finds what the {} form
# found; the same sweep resumes without running anything.
cmds = os.path.join(RUNS, "cmds.txt")
with open(cmds, "w") as fh:
    fh.write(f"{GUEST} race\n# not a case\n'{GUEST}' \"fserr\"\n/bin/sh -c 'exit 0'\n")
st, rep, text = sweep("cmds", "--seeds", "1..4", "--cases", cmds, *FS)
if rep["runs"] != 12:
    die(f"whole-command cases: {rep['runs']} runs\n{text}")
names = [n for s in range(1, 5) for n in os.listdir(os.path.join(RUNS, "cmds", f"seed-{s}"))]
if any(" " in n or len(n) > 48 for n in names):
    die(f"whole-command cases: directory names {names}")
by_word = lambda rep: sorted((g["signature"], g["case"].split()[-1].strip("'\""), g["seeds"]) for g in rep["groups"])
_, cases_rep = report(os.path.join(RUNS, "cases"))
if by_word(rep) != by_word(cases_rep) or not all(g["case"].startswith((GUEST, f"'{GUEST}'")) for g in rep["groups"]):
    die(f"whole-command cases: {by_word(rep)}\nthe {{}} form: {by_word(cases_rep)}")
st2, rep2, text2 = sweep("cmds", "--seeds", "1..4", "--cases", cmds, *FS)
if "running 0" not in text2 or rep2["groups"] != rep["groups"]:
    die(f"whole-command cases did not resume:\n{text2}")
print(f"whole-command cases: 12 runs of two programs, groups {[(g['case'], g['count']) for g in rep['groups']]}; resumes")

# A fault point that never fires under --buggify is unmet, as a `sometimes` that never holds is
# (exit 2, allowable), when that is not chance: no run of 20 or more reached it. Not reached in a
# smoke run of 4, or forced off (point:LABEL=0), it is noted (exit 0); one that fires is neither.
st, rep, _ = sweep("unreached", "--seeds", "1..20", "--buggify", "--", GUEST)
st1, rep1, _ = sweep("smoke", "--seeds", "1..4", "--buggify", "--", GUEST)
st2, rep2, _ = sweep("quiet", "--seeds", "1..4", "--buggify", "--fault", "point:tried-point=0", "--", GUEST, "point")
st3, rep3, _ = sweep("loud", "--seeds", "1..4", "--buggify", "--fault", "point:tried-point=1000", "--", GUEST, "point")
st4, _ = report("--allow-unmet", "tried-point", os.path.join(RUNS, "unreached"))
noted = lambda r: [x["label"] for x in r["sdk"]["buggify_unfired_noted"]]
if (st, st1, st2, st3, st4) != (2, 0, 0, 0, 0) or rep["sdk"]["buggify_never_fired"] != ["tried-point"] or noted(rep1) != noted(rep2) != ["tried-point"] or noted(rep3) or rep3["sdk"]["buggify_never_fired"]:
    die(f"buggify never fired: 20 runs exit {st} {rep['sdk']}; smoke exit {st1}; forced off exit {st2} {rep2['sdk']}; firing exit {st3}; allowed exit {st4}")
print("a fault point never reached in 20 runs under --buggify: exit 2, allowed: 0; in 4 runs, or forced off: noted, exit 0; one that fired: 0")

# A host file that changes between the run and its replay: inputs-changed, not a finding.
# Without the change (red/green), the same failure is a finding that replays identically.
host = os.path.join(RUNS, "host")
os.makedirs(host)
val = os.path.join(host, "val")
with open(val, "w") as fh:
    fh.write("0")
st, rep, _ = sweep("steady", "--seeds", "1", "--mount", f"{host}:/h", "--", GUEST, "cat", "/h/val")
if st != 1 or rep["groups"][0]["replay"]["result"] != "identical":
    die(f"steady host file: exit {st} {rep['groups']}")
with open(val, "w") as fh:
    fh.write("1")
st, so, se = patina("replay", "--format", "json", rep["groups"][0]["first"]["dir"])
r = json.loads(so or "{}")
if st != 2 or r.get("outcome") != "error" or r.get("stop") != "inputs-changed":
    die(f"host file changed before the replay: exit {st} {r.get('outcome')} {se[-500:]}")
print(f"host file changed before the replay: {r['outcome']} ({r['message'][:80]}); steady: finding, identical")

# A livelock ends liveness, stop log-limit, at the same record in every run of a seed (the limit
# counts log, not time); a sweep of it is a finding and keeps each run's first and last records
# only, and a replay of such a run still compares.
lim = []
for i in range(2):
    d = os.path.join(RUNS, f"livelock-{i}")
    # lint-allow: seed — the livelock mode never finishes, whatever the seed
    patina("run", "--seed", "1", "--config", cfg("log-limit=1"), "--out", d, "--", GUEST, "livelock")
    lim.append(result(d))
    if os.path.getsize(os.path.join(d, "inc-0", "boundary.log")) > 1 << 20:
        die(f"log-limit 1: the log holds {os.path.getsize(os.path.join(d, 'inc-0', 'boundary.log'))} bytes")
if [(r["outcome"], r["stop"]) for r in lim] != [("liveness", "log-limit")] * 2 or lim[0]["digest"] != lim[1]["digest"]:
    die(f"livelock: {[(r['outcome'], r['stop'], r['digest']) for r in lim]}")
st, rep, text = sweep("livelock", "--seeds", "1..4", "--config", cfg("log-limit=8"), "--", GUEST, "livelock")
kept = sum(os.path.getsize(os.path.join(p, f)) for p, _, fs in os.walk(os.path.join(RUNS, "livelock")) for f in fs)
if st != 1 or [g["stop"] for g in rep["groups"]] != ["log-limit"] or kept > 4 * (5 << 19):
    die(f"livelock sweep: {[(g['signature'], g['count']) for g in rep['groups']]}, {kept} bytes kept\n{text}")
# --keep fail keeps the logs of a group's first three runs; the rest keep their results.
seeds = sorted(r["seed"] for r in rep["groups"][0]["runs"])
whole = [n for n in seeds if os.path.isdir(os.path.join(RUNS, "livelock", f"seed-{n}", "inc-0"))]
if len(seeds) < 4 or whole != seeds[:3]:
    die(f"livelock sweep: runs {seeds}, kept whole {whole}")
st, so, se = patina("replay", "--format", "json", os.path.join(RUNS, "livelock", "seed-2"))
if json.loads(so or "{}").get("stop") != "log-limit":
    die(f"replay of a cut log: exit {st} {so[:300]} {se[-300:]}")
print(f"livelock: log-limit at digest {lim[0]['digest']} twice; a sweep of 4 at log-limit 8 keeps {kept} bytes; a cut run replays")

# Interrupted: the running children end, every remaining directory holds a finished run,
# and the report covers them.
out = os.path.join(RUNS, "interrupted")
p = subprocess.Popen([PATINA, "sweep", "-j", "4", "--seeds", "1..400", "--out", out, "--",
                      "/bin/sh", "-c", "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
# Interrupt once a run has finished, so the sweep is under way with runs in flight.
while p.poll() is None and not any(os.path.exists(os.path.join(out, d, "result.json"))
                                   for d in (os.listdir(out) if os.path.isdir(out) else []) if d.startswith("seed-")):
    time.sleep(0.05)
p.send_signal(signal.SIGINT)
so, se = p.communicate(timeout=30)
left = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "..", "leftovers.py"), out],
                      capture_output=True, text=True)
partial = [d for d in os.listdir(out) if d.startswith("seed-") and not os.path.exists(os.path.join(out, d, "result.json"))]
if p.returncode != 2 or left.returncode != 0 or partial or not os.path.exists(os.path.join(out, "report.json")):
    die(f"interrupted: exit {p.returncode}, leftovers {left.stdout!r}, partial {partial}\n{se[-1000:]}")
done = len([d for d in os.listdir(out) if d.startswith("seed-")])
print(f"interrupted after the first finished run: {done} runs finished and reported, none partial, no process left")

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
