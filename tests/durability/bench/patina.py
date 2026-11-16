"""cost measurement: patina against the existing tool (Patina v0.5.0) on the workloads both can run.

Patina v0.5.0 is built from the tag in a temporary workspace (PATINA = its `patina` binary);
the guests are built with `patina build` from the same sources (PGUESTS: w1 from
tests/guests/rust-threads-files/main.rs, fj from the trial harness against v0.5.0's SDK and the
same fjall checkout). W9 is the same harness ported to environment variables.
Knobs: patina `--crash machine:5` against Patina `--machine-crash-permille 5` (both: a seeded
machine crash at 5 per mille of eligible points), patina `--fault fs-error-permille=2` against
`--fs-error-permille 2`. The eligible points differ (patina: after every operation-log record and
before every sync-class call; Patina: its own operation list), so crash counts per run differ.

1. Per run: process wall of REPS runs (seeds 1..REPS), both pinned to CPU (Patina by taskset).
2. Sweep: SWEEP seeds (default 100), JOBS at a time (default 8), runs per second.
"""
import concurrent.futures as cf
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import *  # noqa

PAT = os.environ["PATINA"]
PG = os.environ["PGUESTS"]
SWEEP = int(os.environ.get("SWEEP", "100"))
JOBS = int(os.environ.get("JOBS", "8"))
W = os.environ["PATINA_WORKLOADS"]
cases = {
    "W1 off": ((W + "/rust-threads-files", ["/guest/rust-threads-files", "correct"], []),
               (PG + "/w1", ["correct"], [])),
    "W1 crash": ((W + "/rust-threads-files", ["/guest/rust-threads-files", "correct"], ["--crash", "machine:5"]),
                 (PG + "/w1", ["correct"], ["--machine-crash-permille", "5"])),
    "W9 off": ((W + "/fjall-harness", ["/guest/fjall-harness-release"], []), (PG + "/fj", [], [])),
    "W9 crash+fs": ((W + "/fjall-harness", ["/guest/fjall-harness-release"], ["--crash", "machine:5", "--fault", "fs-error-permille=2"]),
                    (PG + "/fj", [], ["--machine-crash-permille", "5", "--fs-error-permille", "2"])),
}


def pat_run(art, args, opts, seed, cpu):
    t0 = time.perf_counter_ns()
    r = subprocess.run(["taskset", "-c", str(cpu), PAT, "run", art, "--seed", str(seed), "--format", "json", *opts, "--", *args],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=1800, cwd=OUT)
    t1 = time.perf_counter_ns()
    try:
        d = json.loads(r.stdout)
        res = d.get("result")
        cr = (d.get("crash_restart") or {}).get("crash_count", 0)
    except ValueError:
        res, cr = "no-json", 0
    return (t1 - t0) / 1e6, res, cr


def patina_one(gdir, argv, opts, seed, cpu, tag):
    o = patina_run(f"{OUT}/{tag}-{seed}", argv, guest=gdir, opts=["--seed", str(seed), "--cpu", str(cpu), *opts])
    shutil.rmtree(f"{OUT}/{tag}-{seed}", ignore_errors=True)
    return o["ext_ms"], o["class"], len(o.get("crashes", []))


res = {"loadavg_before": uptime(), "reps": REPS, "sweep": SWEEP, "jobs": JOBS}
for name, ((gdir, argv, sopts), (art, pargs, popts)) in cases.items():
    sw, pw, scl, pcl, scr, pcr = [], [], {}, {}, [], []
    for s in range(1, REPS + 1):
        t, c, cr = patina_one(gdir, argv, sopts, s, CPU, "one")
        sw.append(t); scl[c] = scl.get(c, 0) + 1; scr.append(cr)
        t, c, cr = pat_run(art, pargs, popts, s, CPU)
        pw.append(t); pcl[c] = pcl.get(c, 0) + 1; pcr.append(cr)
    row = {"patina_ms": stats(sw), "patina_ms": stats(pw), "patina_classes": scl, "patina_classes": pcl,
           "patina_crashes": stats(scr), "patina_crashes": stats(pcr)}
    for tool in ("patina", "patina"):
        t0 = time.time()
        cls = {}
        with cf.ThreadPoolExecutor(JOBS) as ex:
            if tool == "patina":
                fs = [ex.submit(patina_one, gdir, argv, sopts, s, (s - 1) % JOBS, "sw") for s in range(1, SWEEP + 1)]
            else:
                fs = [ex.submit(pat_run, art, pargs, popts, s, (s - 1) % JOBS) for s in range(1, SWEEP + 1)]
            for f in cf.as_completed(fs):
                c = f.result()[1]
                cls[c] = cls.get(c, 0) + 1
        el = time.time() - t0
        row[f"{tool}_sweep"] = {"seconds": el, "runs_per_s": SWEEP / el, "classes": cls}
    res[name] = row
    log(f"{name}: per run patina {fmt(row['patina_ms'], ' ms', 1)} {scl} crashes {row['patina_crashes']['median']}; "
        f"patina {fmt(row['patina_ms'], ' ms', 1)} {pcl} crashes {row['patina_crashes']['median']}; "
        f"sweep {SWEEP}x{JOBS}: patina {row['patina_sweep']['runs_per_s']:.1f} runs/s {row['patina_sweep']['classes']}, "
        f"patina {row['patina_sweep']['runs_per_s']:.1f} runs/s {row['patina_sweep']['classes']}")
res["loadavg_after"] = uptime()
save("patina.json", res)
