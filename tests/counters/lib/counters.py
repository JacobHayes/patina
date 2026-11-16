"""Helpers for the counter preemption scripts (counter preemption).

Environment from ./check: PATINA (unprivileged build), PATINA_RT, PATINA_GUESTS, PATINA_WORKLOADS, RUNS.
Counter runs use a copy of $PATINA with CAP_PERFMON (lib/mkcap.sh: content-keyed, one recorded
sudo use per new build). Quick and area scripts print SKIP and pass where it cannot be made
(a host without sudo or PMU); evidence scripts fail."""
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

PATINA = os.environ["PATINA"]
GU = os.environ["PATINA_GUESTS"]
WL = os.environ["PATINA_WORKLOADS"]
RUNS = os.environ["RUNS"]
HERE = os.path.dirname(os.path.abspath(__file__))
JOBS = int(os.environ.get("COUNTERS_JOBS", "8"))
GO = WL + "/go-static"
FAULT = ["--fault", "fs-error-permille=20"]


def die(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def ppatina(required=True):
    """The CAP_PERFMON copy of $PATINA. Without it: fail (required) or print SKIP and exit 0."""
    r = subprocess.run([os.path.join(HERE, "mkcap.sh"), PATINA], capture_output=True, text=True)
    p = r.stdout.strip()
    if r.returncode == 0 and p and os.path.exists(p):
        # The capability is not enough: the host must expose a PMU (a VM may not).
        o = run(p, RUNS + "/pmu-probe", 1, GU, ["--pmu"], ["/guest/counters/compute", "recur"])
        if o.get("pmu") == "on":
            return p
        why = "no counter on this host: pmu " + repr(o.get("pmu"))
    else:
        why = "cannot make the CAP_PERFMON copy of patina: " + r.stderr.strip()
    if required:
        die(why)
    print("SKIP: " + why)
    sys.exit(0)


def outcome(d):
    try:
        return json.load(open(os.path.join(d, "outcome.json")))
    except (OSError, ValueError):
        return None


def last_line(d, inc=None):
    incs = sorted(x for x in os.listdir(d) if x.startswith("inc-")) if os.path.isdir(d) else []
    if not incs:
        return ""
    f = os.path.join(d, incs[-1] if inc is None else inc, "stdout")
    try:
        ls = [l.strip() for l in open(f, errors="replace") if l.strip()]
    except OSError:
        return ""
    return ls[-1] if ls else ""


def prune(d):
    for inc in os.listdir(d) if os.path.isdir(d) else []:
        for f in ("boundary.log", "oplog.data", "live.tree"):
            p = os.path.join(d, inc, f)
            if os.path.exists(p):
                os.remove(p)


def run(patina, out, seed, guest, opts, cmd, keep=False, timeout=900):
    subprocess.run(["rm", "-rf", out])
    os.makedirs(os.path.dirname(out), exist_ok=True)
    args = [patina, "run", "--seed", str(seed), "--out", out, "--guest", guest] + opts + ["--"] + cmd
    try:
        subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    oc = outcome(out) or {"class": "none", "detail": "no outcome", "digest": "-", "wall_ms": 0}
    oc["_last"] = last_line(out)
    if not keep:
        prune(out)
    return oc


def sweep(patina, name, seeds, guest, opts, cmd, jobs=JOBS):
    """One run per seed, `jobs` at a time; boundary logs deleted. Returns {seed: outcome} and
    writes RUNS/name/summary.tsv."""
    base = os.path.join(RUNS, name)
    os.makedirs(base, exist_ok=True)
    with ThreadPoolExecutor(jobs) as ex:
        res = dict(zip(seeds, ex.map(lambda s: run(patina, f"{base}/s{s}", s, guest, opts, cmd), seeds)))
    with open(base + "/summary.tsv", "w") as f:
        f.write("seed\tclass\tdetail\tdigest\twall_ms\tpreempts\tmax_skid\tlast\n")
        for s, o in res.items():
            st = o.get("pmu_stats", {})
            f.write(f"{s}\t{o['class']}\t{o['detail'][:80]}\t{o['digest']}\t{o['wall_ms']}\t{st.get('preempts', '-')}\t{st.get('max_skid', '-')}\t{o['_last']}\n")
    return res


def verify(patina, out, seed, guest, runs, vary, opts, cmd, timeout=7200):
    """`patina verify`; returns (identical, text). Run directories pruned as they are judged."""
    subprocess.run(["rm", "-rf", out])
    os.makedirs(os.path.dirname(out), exist_ok=True)
    args = [patina, "verify", "--seed", str(seed), "--runs", str(runs), "--out", out, "--guest", guest]
    if vary:
        args += ["--vary", vary]
    env = dict(os.environ, PATINA_VERIFY_PRUNE="1")
    try:
        r = subprocess.run(args + opts + ["--"] + cmd, capture_output=True, text=True, timeout=timeout, env=env)
        txt = r.stdout + r.stderr
        return r.returncode == 0 and "identical:" in txt, txt
    except subprocess.TimeoutExpired:
        return False, "timeout"


def skid(res):
    v = [o.get("pmu_stats", {}).get("max_skid", 0) for o in res.values()]
    v = [x if x < 2**63 else x - 2**64 for x in v]
    return max(v) if v else 0


def classes(res):
    c = {}
    for o in res.values():
        k = o["class"] + (": " + o["detail"][:60] if o["class"] not in ("ok", "failed") else "")
        c[k] = c.get(k, 0) + 1
    return c


def preempts(logpath):
    """(count, [(slot, rip, N)...]) of the preempt records in a boundary log."""
    import struct
    out = []
    try:
        data = open(logpath, "rb").read()
    except OSError:
        return 0, []
    for i in range(0, len(data) - 95, 96):
        slot, kind = struct.unpack_from("<HB", data, i + 16)
        if kind == 8:
            rip, n = struct.unpack_from("<QQ", data, i + 24)
            out.append((slot, rip, n))
    return len(out), out


def native(cmd, timeout=600):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    ls = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    return ls[-1] if ls else ""
