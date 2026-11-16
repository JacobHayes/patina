"""tests/run.py: the check runner (./check builds, then runs this).

    run.py quick              the landing gate: every script marked tier=quick
    run.py AREA ...           one area's scripts (tier quick and area) of tests/AREA
    run.py evidence [NAME..]  the evidence scripts (all, or those whose AREA/name contains NAME)
    run.py list               every script with its tier, budget and slots

An area is a directory under tests/ holding check scripts (`*.sh` directly in it); guests/
holds the guests' sources.

A script declares itself in a line `#@ tier=quick|area|evidence budget=SECONDS slots=N`
(defaults: tier=area, budget 120 s, slots 1; slots = sandboxes it runs at once). Scripts run in
parallel, at most CHECK_SLOTS sandboxes at once (default 8), longest budget first. Each gets a
private RUNS directory; a script still running at its budget is killed and fails, as does one
that leaves a process behind (tests/leftovers.py on its RUNS). Passing scripts' run
directories are deleted (CHECK_KEEP=1 keeps them); their output stays in <base>/<area>-<name>.out,
where <base> is under PATINA_CHECK_DIR/runs (./check sets it; default target/patina-check).
The tier total is printed; quick fails above QUICK_CEILING s (600), an area above 300 s.
"""
import os
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECK_DIR = os.environ.get("PATINA_CHECK_DIR") or os.path.join(ROOT, "target", "patina-check")
DEFAULTS = {"quick": 15, "area": 120, "evidence": 1800}
CEILING = {"quick": int(os.environ.get("QUICK_CEILING", "600")), "area": 300, "evidence": None}
TARGET = {"quick": 300, "area": 300, "evidence": 3600}


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
            tier = meta["tier"]
            out.append({"area": area, "name": f[:-3], "path": os.path.join(d, f), "tier": tier,
                        "budget": int(meta.get("budget", DEFAULTS[tier])), "slots": int(meta["slots"])})
    return out


def select(args, allsc):
    if args[0] == "quick":
        return "quick", [s for s in allsc if s["tier"] == "quick"]
    if args[0] == "evidence":
        names = args[1:]
        sel = [s for s in allsc if s["tier"] == "evidence"
               and (not names or any(n in f"{s['area']}/{s['name']}" for n in names))]
        return "evidence", sel
    areas = [a.lower() for a in args]
    for a in areas:
        if not os.path.isdir(os.path.join(HERE, a)):
            sys.exit(f"no area tests/{a}")
    return "area", [s for s in allsc if s["area"] in areas and s["tier"] in ("quick", "area")]


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    allsc = scripts()
    if args[0] == "list":
        for s in allsc:
            print(f"{s['tier']:9} {s['budget']:5} s  slots {s['slots']}  {s['area']}/{s['name']}")
        return 0
    tier, sel = select(args, allsc)
    if not sel:
        sys.exit(f"no scripts for {' '.join(args)}")
    label = "-".join(a.lower() for a in args)[:40]
    base = os.path.join(CHECK_DIR, "runs", time.strftime("%Y%m%dT%H%M%S") + f"-{label}-{os.getpid()}")
    os.makedirs(base)
    slots_total = int(os.environ.get("CHECK_SLOTS", "8"))
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
        env = dict(os.environ, RUNS=runs, PATINA_SCRATCH=os.path.join(runs, "scratch"))
        env.setdefault("PATINA_LOAD_THREADS", "2")
        log = os.path.join(base, f"{s['area']}-{s['name']}.out")
        t0 = time.monotonic()
        with open(log, "w") as fh:
            p = subprocess.Popen(["sh", s["path"]], cwd=ROOT, env=env, stdout=fh, stderr=subprocess.STDOUT,
                                 start_new_session=True)
            try:
                rc = p.wait(timeout=s["budget"])
                why = "" if rc == 0 else f"exit {rc}"
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
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
