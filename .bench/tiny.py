"""tiny.py PATINA GUESTS N GUEST [extra patina run args...]: median wall and phase times of N runs."""
import os, statistics, subprocess, sys, time, shutil, re

pat, guests, n, guest = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
extra = sys.argv[5:]
scratch = os.environ.get("BENCH_DIR", "/tmp/bench-runs")
os.makedirs(scratch, exist_ok=True)
walls, phases = [], {}
names = ["launch", "spawn", "sup_start", "copied", "first_hello", "main_exit", "finish", "exported", "verdict", "waited", "done"]
for i in range(n):
    out = os.path.join(scratch, f"r{i}")
    shutil.rmtree(out, ignore_errors=True)
    t0 = time.monotonic_ns()
    r = subprocess.run([pat, "run", "--seed", "1", "--out", out, "--mount", f"{guests}:/guest"] + extra + ["--", f"/guest/{guest}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=dict(os.environ, PATINA_TEST_TIMING="1"))
    t1 = time.monotonic_ns()
    walls.append((t1 - t0) / 1e6)
    m = re.search(r"patina-timing inc=0 (.*)", r.stderr)
    if m:
        kv = dict(x.split("=") for x in m.group(1).split())
        prev = t0
        for k in names:
            v = int(kv[k])
            phases.setdefault(k, []).append((v - prev) / 1e6)
            prev = v
        phases.setdefault("exit", []).append((t1 - prev) / 1e6)
    shutil.rmtree(out, ignore_errors=True)
med = statistics.median
print(f"{guest} {' '.join(extra)}: wall median {med(walls):.2f} ms (min {min(walls):.2f})")
print("  " + " ".join(f"{k}={med(v):.2f}" for k, v in phases.items()))
