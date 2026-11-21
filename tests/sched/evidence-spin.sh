# Evidence (scheduling points), unprivileged, at the default CPU count:
#  a. The spin table (stock binaries: glibc and hand-written C spin locks with and without a
#     call inside and with and without the spin hint, spin-then-yield, pthread mutex, Rust
#     spin_loop and std Mutex; on arm64 also exclusive-pair spin locks) over seeds
#     1-SPIN_SEEDS (20), stall-ms = 2000, under three settings: system calls only (pause
#     points and spin probes off), pause points only, and the default (both on). Every run
#     must be ok or compute-stall; with the default every run must be ok.
#  b. W1-W9 with their fault settings, seeds 1-SPIN_SEEDS, default settings: outcomes and
#     compute-stalls per workload. W8's `sockets all` fails on its injected resets (the guest
#     does not retry); any compute-stall fails the script.
#  c. Cost of pause points: W1-W9, seeds 1-5, faults off, cpus 4, one run at a time pinned
#     to one core: median wall_ms with pause points off and on, and of a build without them
#     when PATINA_BASE names one (its scanner does not look for `pause`).
#@ tier=evidence budget=1800 slots=8
HERE=$(cd "$(dirname "$0")" && pwd)
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${PATINA_WORKLOADS:?}" "${RUNS:?}"
OUT=$RUNS/evidence-spin PYTHONPATH=$HERE/../durability/bench python3 -I - <<'PY'
import os, sys, statistics
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.environ["PYTHONPATH"])
from lib import patina_run, OUT, log
from workloads import WL, ORDER

N = int(os.environ.get("SPIN_SEEDS", "20"))
GU = os.environ["PATINA_GUESTS"]
fail = []
SETTINGS = [("system calls only", ["pause-points=false", "spin-probes=false"]),
            ("pause points", ["spin-probes=false"]),
            ("default", [])]
TABLE = [("C pthread_spin_lock, call inside", ["/guest/spinwait", "glibc-spin"]),
         ("C own spin lock, call inside", ["/guest/spinwait", "own-spin"]),
         ("C own spin lock, no hint, call inside", ["/guest/spinwait", "own-spin-nohint"]),
         ("C own spin lock, no call inside", ["/guest/spinwait", "own-spin-nocall"]),
         ("C spin 100 then sched_yield", ["/guest/spinwait", "bounded"]),
         ("C pthread_mutex", ["/guest/spinwait", "mutex"]),
         ("Rust spin lock (spin_loop), call inside", ["/guest/rs-spin", "spin"]),
         ("Rust std Mutex", ["/guest/rs-spin", "mutex"])]
if os.uname().machine == "aarch64":
    TABLE += [("C ldxr/stxr swap spin lock, call inside", ["/guest/llsc-spin", "xchg"]),
              ("C ldxr/stxr compare spin lock, call inside", ["/guest/llsc-spin", "cas"])]
cpus = os.cpu_count()


def one(job):
    i, out, argv, guest, opts = job
    o = patina_run(out, argv, guest=guest, opts=opts, cpu=i % cpus)
    return o


def flags(opts):
    """Flag pairs as --flag=value, so that config() leaves values with `=` alone."""
    out, it = [], iter(opts)
    for a in it:
        out.append(a + "=" + next(it) if a.startswith("--") else a)
    return out


def tally(rs):
    c = {}
    for o in rs:
        k = o["outcome"] + ("/" + o["stop"] if o["outcome"] != "ok" else "")
        c[k] = c.get(k, 0) + 1
    return c


log("== a. spin table, %d seeds each, stall-ms 2000" % N)
with ThreadPoolExecutor(8) as ex:
    for sname, sopts in SETTINGS:
        for k, (name, argv) in enumerate(TABLE):
            jobs = [(s, f"{OUT}/a/{len(sopts)}-{k}-{s}", argv, GU, ["--seed", str(s), "stall-ms=2000"] + sopts)
                    for s in range(1, N + 1)]
            rs = list(ex.map(one, jobs))
            c = tally(rs)
            walls = sorted(o["wall_ms"] for o in rs if o["outcome"] == "ok")
            pp = sum(o["sched"]["pause_points"] for o in rs)
            pre = sum(o["sched"]["preemptions"] for o in rs)
            log(f"{sname:18} | {name:40} | {c} | ok wall median {walls[len(walls) // 2] if walls else '-'} ms"
                f" | pause points {pp}, spin preemptions {pre}")
            if any(k not in ("ok", "unsupported/compute-stall") for k in c):
                fail.append(f"a. {sname} {name}: {c}")
            if sname == "default" and c.get("ok", 0) != N:
                fail.append(f"a. default {name}: {c}")

log("== b. W1-W9, %d seeds each, default settings" % N)
with ThreadPoolExecutor(8) as ex:
    for w in ORDER:
        g, cmd, fo, extra = WL[w]
        jobs = [(s, f"{OUT}/b/{w}-{s}", cmd, g, ["--seed", str(s)] + flags(fo + extra)) for s in range(1, N + 1)]
        rs = list(ex.map(one, jobs))
        c = tally(rs)
        log(f"{w}: {c} | pause points {sum(o['sched']['pause_points'] for o in rs)}, "
            f"spin preemptions {sum(o['sched']['preemptions'] for o in rs)}")
        if c.get("unsupported/compute-stall"):
            fail.append(f"b. {w}: {c}")

import lib
BASE = os.environ.get("PATINA_BASE")
log("== c. cost of pause points: W1-W9, seeds 1-5, faults off, cpus 4, pinned, serial; "
    + ("base: " + BASE if BASE else "no base build (PATINA_BASE)"))
for w in ORDER:
    g, cmd, fo, extra = WL[w]
    row = []
    for name, patina, keys in [("base", BASE, []), ("off", lib.PATINA, ["pause-points=false"]), ("on", lib.PATINA, [])]:
        if not patina:
            row.append(f"{name} -")
            continue
        cur, lib.PATINA = lib.PATINA, patina
        rs = [patina_run(f"{OUT}/c/{w}-{name}-{s}", cmd, guest=g, opts=["--seed", str(s), "cpus=4"] + keys + flags(extra))
              for s in range(1, 6)]
        lib.PATINA = cur
        ok = [o for o in rs if o["outcome"] == "ok"]
        med = statistics.median(o["wall_ms"] for o in ok) if ok else "-"
        sc = [o.get("sched", {}) for o in rs]
        row.append(f"{name} {med} ms ({len(ok)}/5 ok" + (f", pause sites {max(x.get('pause_sites', 0) for x in sc)},"
                   f" pause points {sum(x.get('pause_points', 0) for x in sc)}" if name != "base" else "") + ")")
    log(f"{w}: " + "; ".join(row))
if fail:
    print("FAIL: " + "; ".join(fail))
    sys.exit(1)
print("all checks passed")
PY
