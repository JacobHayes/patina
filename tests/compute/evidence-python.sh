# Evidence (docs/EVIDENCE.md, compute points, Python): `python3 -m patina` with
# tests/guests/compute/py/pycompute.py.
#  1. `cache` (check-then-act between two threads), seeds 1-200: stock / default compute-gap /
#     compute-gap=16..256 (about 1 to 17 lines) / compute-gap=0; failing seeds, the first one's
#     replay.
#  2. `timer 50`, seeds 1-20 at the seed's gap and at compute-gap=0: outcomes, when the handler
#     ran; seed 1 under verify --runs 20 --vary cpu,load,aslr,sandbox.
#  3. `burn 1000000000` (two threads, each over 10 s of CPU without a system call), seed 1:
#     stock and with compute points.
#  4. Costs, the median of 5 wall times: natively, natively under the runner, under Patina
#     stock, with compute points at seed 1's gap and at compute-gap=0; `loop`, `mix` and W5.
# PATINA_PY (default /usr/bin/python3) names the interpreter in the sandbox; PATINA_PY_MOUNT
# ("DIR:/py") mounts one that is not on the host's /usr.
#@ tier=evidence budget=900 slots=6
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${PATINA_WORKLOADS:?}" "${RUNS:?}"
OUT=$RUNS/evidence-python PY=${PATINA_PY:-/usr/bin/python3} PYM=${PATINA_PY_MOUNT:-} python3 -I - <<'PY'
import json, os, statistics, subprocess, time
from concurrent.futures import ThreadPoolExecutor

P, GU, W, OUT, PY = (os.environ[k] for k in ("PATINA", "PATINA_GUESTS", "PATINA_WORKLOADS", "OUT", "PY"))
MNT = ["--mount", GU + ":/guest:copy"] + (["--mount", os.environ["PYM"]] if os.environ["PYM"] else [])
PC = "/guest/compute/py/pycompute.py"
CP = ["--env", "PYTHONPATH=/guest/compute/py", "--", PY, "-m", "patina", PC]
STOCK = ["--", PY, PC]
os.makedirs(OUT, exist_ok=True)
print("interpreter:", PY, os.environ["PYM"])


def run(name, seed, opts, args, mnt=MNT):
    out = os.path.join(OUT, f"{name}-{seed}")
    subprocess.run(["rm", "-rf", out])
    subprocess.run([P, "run", "--seed", str(seed), "--out", out, *mnt, *opts, *args],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
    with open(os.path.join(out, "result.json")) as f:
        r = json.load(f)
    with open(os.path.join(out, "inc-0", "stdout")) as f:
        r["stdout"] = f.read().strip()
    return out, r


def replay(out):
    t = subprocess.run([P, "replay", out], capture_output=True, text=True).stdout
    return "identical" if t.startswith("identical") else "NOT IDENTICAL"


print("== 1. cache, seeds 1-200")
COLS = [("stock", [], STOCK), ("default", [], CP), ("gap16-256", ["--fault", "compute-gap=16..256"], CP),
        ("gap0", ["--fault", "compute-gap=0"], CP)]
with ThreadPoolExecutor(6) as ex:
    for cn, opts, cmd in COLS:
        res = list(ex.map(lambda s: (s, *run(f"cache-{cn}", s, opts, cmd + ["cache", "200"])), range(1, 201)))
        fails = [(s, out) for s, out, r in res if r["outcome"] == "failure"]
        other = sorted({r["outcome"] for _, _, r in res} - {"ok", "failure"})
        rep = f"; seed {fails[0][0]} replays {replay(fails[0][1])}" if fails else ""
        sw = sorted(r.get("compute", {}).get("switches", 0) for _, _, r in res)
        print(f"{cn:<10} failure {len(fails)}/200{rep}; other outcomes {other or 'none'}; median switches {sw[100]}",
              flush=True)

print("== 2. timer 50, seeds 1-20")
with ThreadPoolExecutor(6) as ex:
    for cn, opts in (("seed gap", []), ("gap0", ["--fault", "compute-gap=0"])):
        res = list(ex.map(lambda s: run(f"timer-{cn[:4]}", s, opts, CP + ["timer", "50"])[1], range(1, 21)))
        ok = sum(r["outcome"] == "ok" and "fired" in r["stdout"] and "did not" not in r["stdout"] for r in res)
        h = sorted(int(r["stdout"].split("handler_ns=")[1]) for r in res if "handler_ns=" in r["stdout"])
        stops = sorted(r["compute"]["deadline_stops"] for r in res)
        print(f"{cn}: {ok}/20 fired; handler at {h[0]}..{h[-1]} virtual ns; deadline stops {stops[0]}..{stops[-1]}",
              flush=True)
_, r = run("timer-stock", 1, [], STOCK + ["timer", "50"])
print(f"stock seed 1: {r['outcome']}: {r['stdout']}")
v = subprocess.run([P, "verify", "--runs", "20", "--vary", "cpu,load,aslr,sandbox", "--seed", "1", "--out",
                    os.path.join(OUT, "timer-verify"), *MNT, *CP, "timer", "50"], capture_output=True, text=True)
print("verify:", [l for l in v.stdout.splitlines() if l.startswith(("identical", "differ"))] or v.stdout[-300:])

print("== 3. burn 1000000000, seed 1")
for cn, cmd in (("stock", STOCK), ("compute points", CP)):
    t = time.monotonic()
    _, r = run(f"burn-{cn[:5]}", 1, [], cmd + ["burn", "1000000000"])
    c = r.get("compute", {})
    print(f"{cn}: {r['outcome']}/{r.get('stop')}: {r['stdout'] or r.get('message')}; switches {c.get('switches')}; "
          f"{time.monotonic() - t:.0f} s", flush=True)

print("== 4. costs (ms, median of 5)")


NATIVE = os.path.join(OUT, "native")  # the native runs' working directory (W5 writes files)
os.makedirs(NATIVE, exist_ok=True)


def med(cmd, env=None):
    ts = []
    for _ in range(5):
        t = time.monotonic()
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=NATIVE)
        ts.append((time.monotonic() - t) * 1000)
    return round(statistics.median(ts))


PROGS = [("loop 3000000", GU, ["compute/py/pycompute.py", "loop", "3000000"]),
         ("mix 10", GU, ["compute/py/pycompute.py", "mix", "10"]),
         ("W5 local", W + "/cpython", ["w5.py", "local"])]
for name, d, args in PROGS:
    mnt = ["--mount", d + ":/guest:copy", "--mount", GU + "/compute/py:/sdk"] + MNT[2:]
    env = dict(os.environ, PYTHONPATH=GU + "/compute/py")
    host = PY if not os.environ["PYM"] else None
    nat = med([host, os.path.join(d, args[0]), *args[1:]], env) if host else "-"
    natp = med([host, "-m", "patina", os.path.join(d, args[0]), *args[1:]], env) if host else "-"
    sim = ["--env", "PYTHONPATH=/sdk", "--"]
    stock = med([P, "run", "--seed", "1", "--out", os.path.join(OUT, "cost"), *mnt, *sim, PY, "/guest/" + args[0], *args[1:]])
    cp = med([P, "run", "--seed", "1", "--out", os.path.join(OUT, "cost"), *mnt, *sim, PY, "-m", "patina",
              "/guest/" + args[0], *args[1:]])
    with open(os.path.join(OUT, "cost", "result.json")) as f:
        c = json.load(f).get("compute", {})
    cp0 = med([P, "run", "--seed", "1", "--out", os.path.join(OUT, "cost"), "--fault", "compute-gap=0", *mnt, *sim, PY,
               "-m", "patina", "/guest/" + args[0], *args[1:]])
    print(f"{name}: native {nat}, native -m patina {natp}; Patina stock {stock}, compute points {cp} "
          f"(gap {c.get('gap')}, {c.get('events', 0) // 15} lines and jumps, {c.get('switches')} switches), "
          f"compute-gap=0 {cp0}", flush=True)
PY
