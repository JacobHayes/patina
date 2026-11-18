"""tests/run.py: the check runner (./check builds, then runs this).

    run.py quick              the landing gate: every script in tier quick
    run.py AREA ...           one area's scripts (tier quick and area) of tests/AREA
    run.py release            the release gate (and the nightly job): every script in tier release
    run.py evidence [NAME..]  the evidence scripts (all, or those whose AREA/name contains NAME)
    run.py list               every script with its tiers, budget and slots

Before any script runs, it prints the build under test (PATINA: the version and SHA-256 that
run.json records) and refuses a binary older than any source in its cargo dep-info (a build
that failed or was skipped).

An area is a directory under tests/ holding check scripts (`*.sh` directly in it); guests/
holds the guests' sources.

A script declares itself in a line `#@ tier=TIER[,TIER] budget=SECONDS slots=N arch=MACHINE`
(tiers quick, area, release, evidence; defaults: tier=area, budget 120 s, slots 1, every
architecture; slots = sandboxes it runs at once; arch = the only `uname -m` it runs on, the
others skip it and count it). A script in two tiers may set `budget-TIER=SECONDS` for the
second; it sees the tier it runs for in CHECK_TIER. Scripts run in
parallel, at most CHECK_SLOTS sandboxes at once (default half the CPUs, at least 8), longest
budget first. Each gets a
private RUNS directory; a script still running at its budget is killed with its whole session
and fails, as does one that leaves a process behind (tests/leftovers.py on its RUNS; those are
killed too, so a failed script's directory is quiet when it is kept or uploaded). Passing scripts' run
directories are deleted (CHECK_KEEP=1 keeps them); their output stays in <base>/<area>-<name>.out,
where <base> is under PATINA_CHECK_DIR/runs (./check sets it; default target/patina-check).
The tier total is printed; quick fails above QUICK_CEILING s (600), an area above 300 s, release
above 600 s.
"""
import hashlib
import os
import platform
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
                        "tiers": tiers, "budget": budget, "slots": int(meta["slots"]), "arch": meta.get("arch"),
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
    return "area", [s for s in allsc if s["area"] in areas and {"quick", "area"} & set(s["tiers"])]


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


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    allsc = scripts()
    if args[0] == "list":
        for s in allsc:
            arch = f"  arch {s['arch']}" if s["arch"] else ""
            more = "".join(f"  {t} {b} s" for t, b in s["budgets"].items() if b != s["budget"])
            print(f"{s['tier']:13} {s['budget']:5} s  slots {s['slots']}  {s['area']}/{s['name']}{arch}{more}")
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
    slots_total = int(os.environ.get("CHECK_SLOTS", max(8, (os.cpu_count() or 8) // 2)))
    keep = os.environ.get("CHECK_KEEP") == "1" or tier == "evidence"
    print(f"== {tier}: {len(sel)} scripts, at most {slots_total} sandboxes at once; output in {base}", flush=True)

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
        env.setdefault("PATINA_LOAD_THREADS", "2")
        log = os.path.join(base, f"{s['area']}-{s['name']}.out")
        t0 = time.monotonic()
        with open(log, "w") as fh:
            p = subprocess.Popen(STRICT + [s["path"]], cwd=ROOT, env=env, stdout=fh, stderr=subprocess.STDOUT,
                                 start_new_session=True)
            try:
                rc = p.wait(timeout=s["budget"])
                why = "" if rc == 0 else f"exit {rc}"
            except subprocess.TimeoutExpired:
                kill_session(p.pid)
                p.wait()
                why = f"over budget ({s['budget']} s), killed"
        dt = time.monotonic() - t0
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
        ok = not why
        if ok and not keep:
            subprocess.run(["rm", "-rf", runs])
        with lock:
            free[0] += need
            lock.notify_all()
            results.append((s, ok, dt, why))
            print(f"{'PASS' if ok else 'FAIL'} {s['area']}/{s['name']} {dt:.1f} s (budget {s['budget']})"
                  + ("" if ok else f": {why} (see {log})"), flush=True)
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
        fh.write("area\tscript\ttier\tresult\tseconds\tbudget\n")
        for s, ok, dt, _ in sorted(results, key=lambda r: -r[2]):
            fh.write(f"{s['area']}\t{s['name']}\t{s['tier']}\t{'PASS' if ok else 'FAIL'}\t{dt:.1f}\t{s['budget']}\n")
    print("== slowest:")
    for s, ok, dt, _ in sorted(results, key=lambda r: -r[2])[:10]:
        print(f"   {dt:7.1f} s  {s['area']}/{s['name']}")
    nfail = sum(1 for r in results if not r[1])
    load = os.getloadavg()[0]
    print(f"== {tier}: {len(results) - nfail} passed, {nfail} failed; wall {wall:.0f} s (target {TARGET[tier]} s), "
          f"script time {sum(r[2] for r in results):.0f} s; load average {load:.1f}")
    ceil = CEILING[tier]
    if ceil and wall > ceil:
        print(f"FAIL: the {tier} tier took {wall:.0f} s, over its {ceil} s ceiling: cut or speed up, do not raise it")
        return 1
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
