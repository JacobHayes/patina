"""Helpers for the counter preemption scripts (counter preemption).

Environment from ./check: PATINA (unprivileged build), PATINA_GUESTS, PATINA_WORKLOADS, RUNS.
Counter runs use a copy of $PATINA with CAP_PERFMON (lib/mkcap.sh: content-keyed, one recorded
sudo use per new build). Quick and area scripts print SKIP and pass where it cannot be made
(a host without sudo or PMU); evidence scripts fail. That SKIP is `SKIP: host: REASON`: the
host cannot run counters at all (scripts/land says so only then), unlike a script's own SKIP
(a tool it lacks)."""
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
PMU = ["--preempt", "branches"]


TEST_KEYS = ("stall-ms", "host-cpu", "pause-points", "spin-probes")


def config(opts):
    """Option lists hold flags, config keys (`KEY=VALUE`, e.g. "pmu-slice=100..100") and test
    inputs (`stall-ms=2000`, AGENTS.md "Test inputs"): the keys go into a patina.toml
    (tests/cfg), passed as --config; test inputs into the environment. A flag's value
    (`--fault fs-error-permille=20`) stays with its flag. Returns (arguments, environment)."""
    keys, rest, env = [], [], dict(os.environ)
    for i, o in enumerate(opts):
        flag_value = i > 0 and opts[i - 1].startswith("--") and "=" not in opts[i - 1]
        if "=" in o and not o.startswith("-") and not flag_value:
            k, v = o.split("=", 1)
            if k in TEST_KEYS:
                env["PATINA_TEST_" + k.upper().replace("-", "_")] = v
            else:
                keys.append(o)
        else:
            rest.append(o)
    if not keys:
        return rest, env
    f = subprocess.run([os.environ["PATINA_CFG"]] + keys, capture_output=True, text=True, check=True).stdout.strip()
    return ["--config", f] + rest, env


def pmu(o):
    """"on" when a result ran with counter preemption, else None."""
    return "on" if (o.get("sched") or {}).get("mode") == "branches" else None


def die(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def ppatina(required=True):
    """The CAP_PERFMON copy of $PATINA. Without it: fail (required) or print SKIP and exit 0."""
    r = subprocess.run([os.path.join(HERE, "mkcap.sh"), PATINA], capture_output=True, text=True)
    p = r.stdout.strip()
    if r.returncode == 0 and p and os.path.exists(p):
        # The capability is not enough: the host must expose a PMU (a VM may not) of a
        # supported CPU family; otherwise --preempt branches refuses and says why.
        subprocess.run(["rm", "-rf", RUNS + "/pmu-probe"])
        t = subprocess.run([p, "run", "--seed", "1", "--out", RUNS + "/pmu-probe", "--mount", GU + ":/guest:copy"] + PMU
                           + ["--", "/guest/counters/compute", "recur"], capture_output=True, text=True)
        o = outcome(RUNS + "/pmu-probe")
        if o and pmu(o) == "on":
            return p
        why = "no counters on this host: " + (t.stderr.strip() or repr(o))
    else:
        why = "cannot make the CAP_PERFMON copy of patina: " + r.stderr.strip()
    if required:
        die(why)
    print("SKIP: host: " + why)
    sys.exit(0)


def outcome(d):
    try:
        return json.load(open(os.path.join(d, "result.json")))
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
    extra, env = config(opts)
    args = [patina, "run", "--seed", str(seed), "--out", out, "--mount", guest + ":/guest:copy"] + extra + ["--"] + cmd
    try:
        subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        pass
    oc = outcome(out) or {"outcome": "none", "message": "no outcome", "digest": "-", "wall_ms": 0}
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
        f.write("seed\toutcome\tmessage\tdigest\twall_ms\tpreempts\tmax_skid\tlast\n")
        for s, o in res.items():
            st = o.get("counters", {}).get("pmu", {})
            f.write(f"{s}\t{o['outcome']}\t{o['message'][:80]}\t{o['digest']}\t{o['wall_ms']}\t{st.get('preempts', '-')}\t{st.get('max_skid', '-')}\t{o['_last']}\n")
    return res


def verify(patina, out, seed, guest, runs, vary, opts, cmd, timeout=7200):
    """`patina verify`; returns (identical, text). Run directories pruned as they are judged."""
    subprocess.run(["rm", "-rf", out])
    os.makedirs(os.path.dirname(out), exist_ok=True)
    args = [patina, "verify", "--seed", str(seed), "--runs", str(runs), "--out", out, "--mount", guest + ":/guest:copy"]
    if vary:
        args += ["--vary", vary]
    extra, env = config(opts)
    env["PATINA_TEST_VERIFY_PRUNE"] = "1"
    try:
        r = subprocess.run(args + extra + ["--"] + cmd, capture_output=True, text=True, timeout=timeout, env=env)
        txt = r.stdout + r.stderr
        return "identical:" in txt, txt
    except subprocess.TimeoutExpired:
        return False, "timeout"


def skid(res):
    v = [o.get("counters", {}).get("pmu", {}).get("max_skid", 0) for o in res.values()]
    v = [x if x < 2**63 else x - 2**64 for x in v]
    return max(v) if v else 0


def classes(res):
    c = {}
    for o in res.values():
        k = o["outcome"] + (": " + o["message"][:60] if o["outcome"] not in ("ok", "failure", "crash") else "")
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


def sample_rate():
    """The kernel's perf_event_max_sample_rate (it throttles an event above it per tick, and
    lowers it when its interrupts take long, as on a loaded virtual machine)."""
    try:
        return open("/proc/sys/kernel/perf_event_max_sample_rate").read().strip()
    except OSError:
        return "?"


def late(o):
    """A run that failed closed because an overflow interrupt came later than the margin."""
    return o.get("outcome") == "internal" and o.get("stop") == "pmu-late"


def exact(patina, out, n, mh, mc, cmd, opts=()):
    """The same fixed N reached by hops only (margin mh: every branch counted by the runtime, the
    definition of the stop) and through the counter (margin mc). Returns (verdict, hops result,
    counter result, preempt records of the hops run): verdict "equal", "late" (the counter run
    failed closed: stop pmu-late), "not ok" or "DIFFERS". A difference keeps both runs' logs and
    returns the first differing record (`patina log diff`) as the verdict's second line; other
    logs are pruned."""
    base = ["pmu-short-permille=0", f"pmu-slice={n}..{n}", "pmu-short-max=1", "stall-ms=600000"] + list(opts)
    a = run(patina, f"{out}-hops", 1, GU, base + [f"pmu-margin={mh}"], cmd, keep=True)
    b = run(patina, f"{out}-counter", 1, GU, base + [f"pmu-margin={mc}"], cmd, keep=True)
    ca, _ = preempts(f"{out}-hops/inc-0/boundary.log")
    if a["outcome"] != "ok" or (b["outcome"] != "ok" and not late(b)):
        v = "not ok"
    elif late(b):
        v = "late"
    elif a["digest"] == b["digest"]:
        v = "equal"
    else:
        r = subprocess.run([patina, "log", "diff", f"{out}-hops/inc-0/boundary.log", f"{out}-counter/inc-0/boundary.log"],
                           capture_output=True, text=True)
        v = "DIFFERS (logs kept: " + out + "-hops, -counter)\n" + "\n".join((r.stdout + r.stderr).strip().splitlines()[:3])
    if not v.startswith("DIFFERS"):
        prune(f"{out}-hops")
        prune(f"{out}-counter")
    return v, a, b, ca


def native(cmd, timeout=600):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    ls = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    return ls[-1] if ls else ""
