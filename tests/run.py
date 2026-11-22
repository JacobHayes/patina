"""tests/run.py: the check runner (./check builds, then runs this).

    run.py quick              the landing gate: every script in tier quick
    run.py AREA ...           one area's scripts (tier quick and area) of tests/AREA
    run.py release            the release gate (and the nightly job): every script in tier release
    run.py evidence [NAME..]  the evidence scripts (all, or those whose AREA/name contains NAME)
    run.py list               every script with its tiers, budget and slots
    run.py areas              the areas with a quick or area script for this machine (the nightly
                              runs each with ./check AREA, under its own ceiling)

Before any script runs, it prints the build under test (PATINA: the version and SHA-256 that
run.json records) and refuses a binary older than any source in its cargo dep-info (a build
that failed or was skipped).

An area is a directory under tests/ holding check scripts (`*.sh` directly in it); guests/
holds the guests' sources.

A script declares itself in a line `#@ tier=TIER[,TIER] budget=SECONDS slots=N arch=MACHINE`
(tiers quick, area, release, evidence; defaults: tier=area, budget 120 s, slots 1, every
architecture; slots = the CPUs it keeps busy, its CPU time over its wall time as measured on the
arm64 runner, to the half (0.5 for one that mostly waits); arch = the only `uname -m` it runs on,
the others skip it and count it). A script in two tiers may set `budget-TIER=SECONDS` for the
second; it sees the tier it runs for in CHECK_TIER. Scripts run in
parallel, their slots together at most CHECK_SLOTS (default half the CPUs, at least 8), longest
budget first. Each gets a
private RUNS directory; a script still running at its budget is killed with its whole session
and fails (first tests/hang.py writes RUNS/hang.txt: its processes and threads, what each was
doing, and the last records of every run it left unfinished), as does one that leaves a process behind (tests/leftovers.py on its RUNS; those are
killed too, so a failed script's directory is quiet when it is kept or uploaded). Passing scripts' run
directories are deleted (CHECK_KEEP=1 keeps them); their output stays in <base>/<area>-<name>.out,
where <base> is under PATINA_CHECK_DIR/runs (./check sets it; default target/patina-check).
The tier total is printed, with its share of the ceiling and the time the same scripts would take
on four CPUs (the CI runners' four cores: the sum over scripts of time x min(slots, 4) / 4);
quick fails above QUICK_CEILING s (600), an area above 300 s, release above 600 s (each times
the calibration factor, below).
CHECK_SOFT_CEILING=PCT (scripts/land sets 50) also fails a tier whose four-sandbox time is over
PCT% of its ceiling. A CI runner's wall time is about the four-sandbox time of its own script
times, and those of the arm64 runner, the slower one, are near a loaded development host's: a
tier past half its ceiling here has used up the margin that keeps arm64 green while the host or
the runner is slow. The fix is to cut, not to raise either.

Calibration: before any script, the runner times a small piece of the scripts' own work (a
sweep of four seeds of a guest that forks and execs, on four sandboxes, with a copied mount),
once, or three times when the first is slower than the reference, and divides the median by
REFERENCE for the machine: the slowest of that time
seen on an unloaded CI runner of the architecture. The factor, bounded to [1, 3], multiplies
every budget and the tier ceiling, and is printed at the start and in the summary. An unloaded
runner or any faster host measures at most the reference and runs at 1x, so a script that has
grown is caught exactly as without calibration; a runner that is slow at everything (CI's
hosted runners vary by up to 3x) gets the time it needs. A calibration that fails runs at 1x.
The soft ceiling is not scaled: it measures growth on the host that lands, where a loaded host
waits for load to fall rather than land a tier that has used up its margin.
"""
import hashlib
import os
import platform
from select import select as fd_ready
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECK_DIR = os.environ.get("PATINA_CHECK_DIR") or os.path.join(ROOT, "target", "patina-check")
DEFAULTS = {"quick": 15, "area": 120, "release": 300, "evidence": 1800}
CEILING = {"quick": int(os.environ.get("QUICK_CEILING", "600")), "area": 300, "release": 600, "evidence": None}
# Every script runs under bash in strict mode, whatever its first line says: a failed command, a
# failed command anywhere in a pipeline (also inside $(...)) and an unset variable stop it, and
# the line and command that stopped it are printed. An expected failure is written out: `if !
# cmd`, `cmd && die ...`, `st=0; cmd || st=$?` (tests/lint.py checks what this cannot).
STRICT = ["bash", "-euo", "pipefail", "-E", "-O", "inherit_errexit", "-c",
          'trap \'s=$?; echo "strict: ${BASH_SOURCE[0]}:$LINENO: exit $s: $BASH_COMMAND" >&2\' ERR; . "$0"']
TARGET = {"quick": 300, "area": 300, "release": 600, "evidence": 3600}
# Calibration (the module's docstring): the reference time of the probe in seconds, by machine,
# and the bounds of the factor.
REFERENCE = {"x86_64": 2.5, "aarch64": 3.0}
FACTOR_MAX = 3.0


def calibrate(base):
    """The factor for budgets and the ceiling, and what it was measured from (for the log)."""
    ref = REFERENCE.get(platform.machine())
    guests = os.environ.get("PATINA_GUESTS")
    if not ref or not guests:
        return 1.0, "no reference for this machine" if not ref else "no PATINA_GUESTS"
    times = []
    # One probe at the reference or faster is the answer (1x); a slower one is confirmed by two
    # more, and their median taken.
    for i in range(3):
        if i == 1 and times[0] <= ref:
            break
        out = os.path.join(base, "calibration", str(i))
        t0 = time.monotonic()
        r = subprocess.run([os.environ["PATINA"], "sweep", "--seeds", "1..4", "-j", "4", "--keep", "fail",
                            "--out", out, "--mount", f"{guests}:/guest:copy", "--", "/guest/fork-exec"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        times.append(time.monotonic() - t0)
        subprocess.run(["rm", "-rf", out])
        if r.returncode != 0:
            return 1.0, f"calibration failed (exit {r.returncode}: {r.stdout.strip()[-200:]})"
    t = sorted(times)[len(times) // 2]
    factor = min(FACTOR_MAX, max(1.0, t / ref))
    return factor, f"probe {t:.2f} s, reference {ref:.2f} s"


def scripts():
    out = []
    for area in sorted(os.listdir(HERE)):
        d = os.path.join(HERE, area)
        if area == "guests" or not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".sh"):
                continue
            meta = {"tier": "area", "slots": "1"}
            with open(os.path.join(d, f)) as fh:
                for line in fh:
                    if line.startswith("#@"):
                        meta.update(kv.split("=", 1) for kv in line[2:].split())
            tiers = meta["tier"].split(",")
            budget = int(meta.get("budget", DEFAULTS[tiers[0]]))
            out.append({"area": area, "name": f[:-3], "path": os.path.join(d, f), "tier": meta["tier"],
                        "tiers": tiers, "budget": budget, "slots": float(meta["slots"]), "arch": meta.get("arch"),
                        "budgets": {t: int(meta.get(f"budget-{t}", budget)) for t in tiers}})
    return out


def select(args, allsc):
    if args[0] in ("quick", "release"):
        return args[0], [dict(s, budget=s["budgets"][args[0]]) for s in allsc if args[0] in s["tiers"]]
    if args[0] == "evidence":
        names = args[1:]
        sel = [s for s in allsc if "evidence" in s["tiers"]
               and (not names or any(n in f"{s['area']}/{s['name']}" for n in names))]
        return "evidence", sel
    areas = [a.lower() for a in args]
    for a in areas:
        if not os.path.isdir(os.path.join(HERE, a)):
            sys.exit(f"no area tests/{a}")
    return "area", [dict(s, budget=s["budgets"].get("area", s["budget"])) for s in allsc
                    if s["area"] in areas and {"quick", "area"} & set(s["tiers"])]


def build_under_test():
    """The build the scripts test (PATINA): the identity run.json records ("VERSION SHA256"),
    or exit when it is missing or older than any source its dep-info (BINARY.d, written by
    cargo) names: a build that failed or was skipped left an earlier binary behind, and
    scripts run against it would test old code."""
    exe = os.environ.get("PATINA")
    if not exe:
        sys.exit("run.py: PATINA is not set: run it through ./check, which builds patina first")
    try:
        built = os.stat(exe).st_mtime_ns
        with open(exe + ".d") as f:
            deps = f.read().replace("\\\n", " ").split("\n", 1)[0].split(": ", 1)[1]
    except (OSError, IndexError) as e:
        sys.exit(f"run.py: the build under test: {e}")
    # Paths with spaces are escaped as "\ " in dep-info.
    paths = [p.replace("\0", " ") for p in deps.replace("\\ ", "\0").split()]
    newer = []
    for p in paths:
        for d, _, files in os.walk(p) if os.path.isdir(p) else [(os.path.dirname(p), [], [os.path.basename(p)])]:
            for n in files:
                q = os.path.join(d, n)
                try:
                    if os.stat(q).st_mtime_ns > built:
                        newer.append(q)
                except OSError:
                    newer.append(q + " (missing)")
    if newer:
        sys.exit(f"run.py: {exe} is older than {len(newer)} of its sources (first: {newer[0]}): "
                 "its build failed or was skipped; build it (./check does) before running scripts")
    version = subprocess.run([exe, "--version"], stdout=subprocess.PIPE, text=True, check=True).stdout.split()[-1]
    h = hashlib.sha256()
    with open(exe, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(built / 1e9))
    return f"{version} {h.hexdigest()}", stamp


def kill_session(sid):
    """SIGKILL every process of session SID (a script runs in its own session; a process
    group is not enough: `timeout` and other job-control tools move to their own group) until
    none is left."""
    for _ in range(100):
        pids = []
        for name in os.listdir("/proc"):
            if name.isdigit():
                try:
                    with open(f"/proc/{name}/stat") as f:
                        st = f.read().rsplit(")", 1)[1].split()
                    if st[0] != "Z" and int(st[3]) == sid:
                        pids.append(int(name))
                except (OSError, IndexError, ValueError):
                    pass
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.05)


def hang(args):
    """tests/hang.py: what a script killed over its budget was doing, into RUNS/hang.txt; its
    snapshot's CPU time of the script's processes in seconds (None when it gave none)."""
    try:
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "hang.py")] + args, timeout=300,
                           stdout=subprocess.PIPE, text=True)
    except subprocess.TimeoutExpired:
        return None
    for line in r.stdout.splitlines():
        if line.startswith("cpu "):
            return float(line.split()[1])
    return None


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    allsc = scripts()
    if args[0] == "list":
        for s in allsc:
            arch = f"  arch {s['arch']}" if s["arch"] else ""
            more = "".join(f"  {t} {b} s" for t, b in s["budgets"].items() if b != s["budget"])
            print(f"{s['tier']:13} {s['budget']:5} s  slots {s['slots']:g}  {s['area']}/{s['name']}{arch}{more}")
        return 0
    if args[0] == "areas":
        on = [s for s in allsc if {"quick", "area"} & set(s["tiers"]) and s["arch"] in (None, platform.machine())]
        print("\n".join(sorted({s["area"] for s in on})))
        return 0
    tier, sel = select(args, allsc)
    machine = platform.machine()
    skipped = [s for s in sel if s["arch"] not in (None, machine)]
    sel = [s for s in sel if s not in skipped]
    if skipped:
        print(f"== {len(skipped)} scripts skipped: marked for another architecture than {machine}", flush=True)
    if not sel:
        sys.exit(f"no scripts for {' '.join(args)}")
    build, stamp = build_under_test()
    print(f"== patina under test: {build} (built {stamp})", flush=True)
    label = "-".join(a.lower() for a in args)[:40]
    base = os.path.join(CHECK_DIR, "runs", time.strftime("%Y%m%dT%H%M%S") + f"-{label}-{os.getpid()}")
    os.makedirs(base)
    slots_total = float(os.environ.get("CHECK_SLOTS", max(8, len(os.sched_getaffinity(0)) // 2)))
    keep = os.environ.get("CHECK_KEEP") == "1" or tier == "evidence"
    print(f"== {tier}: {len(sel)} scripts, at most {slots_total:g} slots (CPUs) at once; output in {base}", flush=True)
    factor, why = calibrate(base)
    for s in sel:
        s["budget"] = round(s["budget"] * factor)
    print(f"== budgets and ceiling x{factor:.2f} ({why})", flush=True)

    lock = threading.Condition()
    free = [slots_total]
    results = []
    t_start = time.monotonic()

    def one(s):
        need = min(s["slots"], slots_total)
        with lock:
            while free[0] < need:
                lock.wait()
            free[0] -= need
        runs = os.path.join(base, s["area"], s["name"])
        os.makedirs(runs)
        env = dict(os.environ, RUNS=runs, PATINA_SCRATCH=os.path.join(runs, "scratch"), CHECK_TIER=tier)
        env.setdefault("PATINA_TEST_LOAD_THREADS", "2")
        log = os.path.join(base, f"{s['area']}-{s['name']}.out")
        t0 = time.monotonic()
        with open(log, "w") as fh:
            p = subprocess.Popen(STRICT + [s["path"]], cwd=ROOT, env=env, stdout=fh, stderr=subprocess.STDOUT,
                                 start_new_session=True)
            # Waited for with wait4: the script's CPU time, its reaped descendants' included. A
            # killed script's descendants are not reaped by it, so its CPU time is the process
            # tree's, read from /proc just before the kill (tests/hang.py snapshot).
            pidfd = os.pidfd_open(p.pid)
            ready, _, _ = fd_ready([pidfd], [], [], s["budget"])
            os.close(pidfd)
            tree = None
            if ready:
                _, st, ru = os.wait4(p.pid, 0)
                p.returncode = os.waitstatus_to_exitcode(st)
                why = "" if p.returncode == 0 else f"exit {p.returncode}"
            else:
                tree = hang(["snapshot", str(p.pid), runs])
                kill_session(p.pid)
                _, _, ru = os.wait4(p.pid, 0)
                p.returncode = -9
                why = f"over budget ({s['budget']} s), killed"
        dt = time.monotonic() - t0
        cpu = max(ru.ru_utime + ru.ru_stime, tree or 0)
        # Nothing of the script's runs may be left (sandbox teardown is asynchronous: 5 s grace).
        left = ""
        for _ in range(50):
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "leftovers.py"), runs],
                               stdout=subprocess.PIPE, text=True)
            left = r.stdout.strip()
            if not left:
                break
            time.sleep(0.1)
        if left:
            why = (why + "; " if why else "") + "processes left: " + left.splitlines()[0]
            # Kill them, so the run directory is quiet when it is kept or uploaded.
            for _ in range(50):
                for line in left.splitlines():
                    try:
                        os.kill(int(line.split()[0]), signal.SIGKILL)
                    except (OSError, ValueError):
                        pass
                time.sleep(0.1)
                r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "leftovers.py"), runs],
                                   stdout=subprocess.PIPE, text=True)
                left = r.stdout.strip()
                if not left:
                    break
        if why.startswith("over budget"):
            hang(["logs", runs])
            why += f"; what it was doing: {os.path.join(runs, 'hang.txt')}"
        ok = not why
        if ok and not keep:
            subprocess.run(["rm", "-rf", runs])
        with lock:
            free[0] += need
            lock.notify_all()
            results.append((s, ok, dt, why, cpu))
            # A pass that skipped its work (no sudo, another kind of host) says so, so a log tells it from a run.
            skip = ""
            if ok:
                with open(log, errors="replace") as fh:
                    skip = next((" (" + l.strip()[:120] + ")" for l in fh if l.startswith("SKIP")), "")
            print(f"{'PASS' if ok else 'FAIL'} {s['area']}/{s['name']} {dt:.1f} s, cpu {cpu:.1f} s (budget {s['budget']})"
                  + (skip if ok else f": {why} (see {log})"), flush=True)
            if not ok:
                with open(log) as fh:
                    for line in fh.readlines()[-5:]:
                        print("    " + line.rstrip(), flush=True)

    threads = []
    for s in sorted(sel, key=lambda s: -s["budget"]):
        t = threading.Thread(target=one, args=(s,))
        t.start()
        threads.append(t)
        time.sleep(0.05)
    for t in threads:
        t.join()
    wall = time.monotonic() - t_start
    with open(os.path.join(base, "summary.tsv"), "w") as fh:
        fh.write("area\tscript\ttier\tresult\tseconds\tcpu\tbudget\n")
        for s, ok, dt, _, cpu in sorted(results, key=lambda r: -r[2]):
            fh.write(f"{s['area']}\t{s['name']}\t{s['tier']}\t{'PASS' if ok else 'FAIL'}\t{dt:.1f}\t{cpu:.1f}\t{s['budget']}\n")
    print("== slowest:")
    for s, ok, dt, _, _ in sorted(results, key=lambda r: -r[2])[:10]:
        print(f"   {dt:7.1f} s  {s['area']}/{s['name']}")
    nfail = sum(1 for r in results if not r[1])
    load = os.getloadavg()[0]
    ceil = CEILING[tier] and round(CEILING[tier] * factor)
    four = sum(min(s["slots"], 4) * dt for s, _, dt, _, _ in results) / 4
    share = lambda t: f"{100 * t / ceil:.0f}% of the {ceil} s ceiling" if ceil else f"target {TARGET[tier]} s"
    print(f"== {tier}: {len(results) - nfail} passed, {nfail} failed; wall {wall:.0f} s ({share(wall)}); "
          f"on 4 CPUs about {four:.0f} s ({share(four)}); script time {sum(r[2] for r in results):.0f} s; "
          f"CPU time {sum(r[4] for r in results):.0f} s; "
          f"load average {load:.1f}; budgets and ceiling x{factor:.2f}")
    if ceil and wall > ceil:
        print(f"FAIL: the {tier} tier took {wall:.0f} s, over its {ceil} s ceiling: cut or speed up, do not raise it")
        return 1
    # Not scaled: a growth check on the host that lands (the module's docstring).
    soft = int(os.environ.get("CHECK_SOFT_CEILING", "0"))
    ceil = CEILING[tier]
    if soft and ceil and four > ceil * soft / 100:
        print(f"FAIL: on 4 CPUs the {tier} tier would take about {four:.0f} s, over {soft}% of its {ceil} s "
              "ceiling: the slower CI runner (arm64) would come near or over it. Cut: move sweeps, matrices "
              "and repetitions to the area or release tier (AGENTS.md); do not raise the ceiling")
        return 1
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
