"""Shared helpers for the cost scripts (run with python3 -I).

Environment: PATINA, PATINA_GUESTS (as ./check sets them), OUT (an output directory). Every patina run is pinned to CPU (default the last core); boundary logs are
deleted after each run (only result.json, stdout and stderr are kept).
"""
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

PATINA = os.environ["PATINA"]
GUESTS = os.environ["PATINA_GUESTS"]
OUT = os.environ["OUT"]
CPU = int(os.environ.get("CPU", str(os.cpu_count() - 1)))
REPS = int(os.environ.get("REPS", "10"))
NATIVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "files", "lib", "native.sh")
os.makedirs(OUT, exist_ok=True)


def log(*a):
    print(*a, flush=True)


def prune(d):
    for root, _dirs, files in os.walk(d):
        for f in files:
            if f in ("boundary.log", "oplog.data", "oplog.meta", "live.tree"):
                os.unlink(os.path.join(root, f))


def config(opts):
    """Option lists hold flags and config keys (`KEY=VALUE`, e.g. "stall-ms=2000"): the keys go
    into a patina.toml (tests/cfg), passed as --config."""
    keys, rest, i = [], [], 0
    while i < len(opts):
        o = opts[i]
        if o.startswith("-") and "=" not in o and i + 1 < len(opts) and not opts[i + 1].startswith("-"):
            rest += [o, opts[i + 1]]  # a flag and its value (`--fault fs-error-permille=5`)
            i += 2
            continue
        (keys if not o.startswith("-") and "=" in o else rest).append(o)
        i += 1
    if not keys:
        return rest
    f = subprocess.run([os.environ["PATINA_CFG"]] + keys, capture_output=True, text=True, check=True).stdout.strip()
    return ["--config", f] + rest


def patina_run(out, args, guest=GUESTS, opts=(), env=None, rt=None, timeout=900, keep_logs=False, cpu=None):
    """One patina run, pinned to `cpu` (default CPU); returns the result dict plus 'ext_ms' (wall
    of the patina process)."""
    shutil.rmtree(out, ignore_errors=True)
    cpu = CPU if cpu is None else cpu
    cmd = ["taskset", "-c", str(cpu), PATINA, "run", "--out", out, "--mount", guest + ":/guest:copy", *config(opts), "--", *args]
    e = dict(os.environ)
    if rt:
        e["PATINA_RT"] = rt
    if env:
        e.update(env)
    t0 = time.perf_counter_ns()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=e, timeout=timeout)
    t1 = time.perf_counter_ns()
    with open(os.path.join(out, "result.json")) as f:
        o = json.load(f)
    o["ext_ms"] = (t1 - t0) / 1e6
    if not keep_logs:
        prune(out)
    return o


def native_run(out, args, guest=GUESTS, sandbox=True, env=None, timeout=900):
    """One native run, pinned to CPU; in the sandbox a run gets (native.sh) unless sandbox=False.
    Returns (wall ms, exit status)."""
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    e = dict(os.environ)
    e["PATINA_GUESTS"] = guest
    envs = []
    for k, v in (env or {}).items():
        envs += ["--env", f"{k}={v}"]
    if sandbox:
        cmd = ["taskset", "-c", str(CPU), "bash", NATIVE, out, *envs, "--", *args]
    else:
        cmd = ["taskset", "-c", str(CPU), *args]
    t0 = time.perf_counter_ns()
    if sandbox:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=e, timeout=timeout)
    else:
        with open(os.path.join(out, "stdout"), "wb") as so, open(os.path.join(out, "stderr"), "wb") as se:
            r = subprocess.run(cmd, stdout=so, stderr=se, env=e, timeout=timeout)
    t1 = time.perf_counter_ns()
    return (t1 - t0) / 1e6, r.returncode


def stats(xs):
    xs = sorted(xs)
    return {"median": statistics.median(xs), "min": xs[0], "max": xs[-1], "n": len(xs)}


def fmt(s, unit="", nd=2):
    return f"{s['median']:.{nd}f}{unit} [{s['min']:.{nd}f}..{s['max']:.{nd}f}]"


def save(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)


def uptime():
    with open("/proc/loadavg") as f:
        return f.read().split()[:3]
