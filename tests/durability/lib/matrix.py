"""cost measurement item 1, the workload matrix: W1-W9, evidence R and D as defined in spec 05.

R: seed 1, faults off: class ok and exit 0; `refused` and `unscanned_exec_mappings` listed.
D: `patina verify --runs COSTS_D_RUNS --vary cpu,load,aslr,sandbox` identical for seeds 1..COSTS_D_SEEDS
   (defaults 20 and 5, as recorded), faults off and with the workload's fault configuration
   (tests/durability/bench/workloads.py); and seeds 1-10, one run each, faults off: number of distinct
   digests (>= 3 required for concurrent workloads).
Self-check: `patina log ops --check` on seed 1 faults off and on (every incarnation).
F: the workload's fault scenario is checked by its own task's area scripts (named per workload
   in the table; ./check TNN).
W4 runs at --cpus 2 (its stall-free setting; spec 05 asks for the default count: see language runtimes).
Usage: matrix.py OUTDIR [W...]. Writes OUTDIR/matrix.tsv and prints the table.
"""
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bench"))
from workloads import WL, ORDER  # noqa

PATINA = os.environ["PATINA"]
out = sys.argv[1]
only = sys.argv[2:] or ORDER
os.makedirs(out, exist_ok=True)
D_RUNS = os.environ.get("COSTS_D_RUNS", "20")
D_SEEDS = int(os.environ.get("COSTS_D_SEEDS", "5"))
F_SCRIPT = {"W1": "storage reproductions 09-w1", "W2": "language runtimes 03-tokio", "W3": "storage reproductions 08-sqlite", "W4": "language runtimes 01-go",
            "W5": "language runtimes 02-cpython", "W6": "language runtimes 04-shell", "W7": "processes 01-fork-exec, 02-exec-matrix, 04-exit-order",
            "W8": "the network wire 05-faults", "W9": "storage reproductions 02-f1 .. 06-f5"}


def outcome(d):
    with open(os.path.join(d, "result.json")) as f:
        return json.load(f)


def prune(d):
    for r, ds, fs in os.walk(d):
        for f in fs:
            if f in ("boundary.log", "oplog.data", "live.tree"):
                os.unlink(os.path.join(r, f))
        for x in list(ds):
            if x == "post-crash":
                shutil.rmtree(os.path.join(r, x), ignore_errors=True)


rows = []
ok_all = True
for w in only:
    gdir, argv, faults, extra = WL[w]
    base = os.path.join(out, w)
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    # R
    rd = os.path.join(base, "r")
    subprocess.run([PATINA, "run", "--seed", "1", "--out", rd, "--mount", gdir + ":/guest:copy", *extra, "--", *argv],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
    o = outcome(rd)
    r_ok = o["outcome"] == "ok" and o["guest"]["exit"] == 0
    # The tracker's self-check (replay of the operation log = the live tree), faults off (the R
    # run) and on (seed 1 with the workload's fault configuration), every incarnation.
    fd = os.path.join(base, "r-faults")
    subprocess.run([PATINA, "run", "--seed", "1", "--out", fd, "--mount", gdir + ":/guest:copy", *extra, *faults, "--", *argv],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
    sc_ok = True
    for d in (rd, fd):
        c = subprocess.run([PATINA, "log", "ops", "--check", d], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
        with open(d + ".oplog-check.txt", "w") as fh:
            fh.write(c.stdout)
        sc_ok &= c.returncode == 0
    prune(rd)
    prune(fd)
    # D
    dres = {}
    for f in ("off", "on"):
        opts = extra + (faults if f == "on" else [])
        same = 0
        classes = []
        for seed in range(1, D_SEEDS + 1):
            vd = os.path.join(base, f"d-{f}-s{seed}")
            p = subprocess.run([PATINA, "verify", "--seed", str(seed), "--runs", D_RUNS, "--vary", "cpu,load,aslr,sandbox",
                                "--out", vd, "--mount", gdir + ":/guest:copy", *opts, "--", *argv],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=7200)
            if p.returncode == 0:
                same += 1
            else:
                with open(os.path.join(base, f"d-{f}-s{seed}.txt"), "w") as fh:
                    fh.write(p.stdout)
            try:
                classes.append(outcome(os.path.join(vd, "run-0"))["outcome"])
            except OSError:
                classes.append("none")
            if p.returncode == 0:
                prune(vd)
        dres[f] = (same, classes)
    digests = set()
    for seed in range(1, 11):
        sd = os.path.join(base, f"seed{seed}")
        subprocess.run([PATINA, "run", "--seed", str(seed), "--out", sd, "--mount", gdir + ":/guest:copy", *extra, "--", *argv],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
        digests.add(outcome(sd)["digest"])
        prune(sd)
    d_ok = dres["off"][0] == D_SEEDS and dres["on"][0] == D_SEEDS and len(digests) >= 3
    ok_all &= r_ok and d_ok and sc_ok
    row = [w, f"{'PASS' if r_ok else 'FAIL'} ({o['outcome']}, exit {o['guest']['exit']}, refused {','.join(o['refused']) or '-'}, "
              f"unscanned {o['labels']['unscanned_exec_mappings']})",
           f"{dres['off'][0]}/{D_SEEDS} identical ({','.join(sorted(set(dres['off'][1])))})",
           f"{dres['on'][0]}/{D_SEEDS} identical ({','.join(sorted(set(dres['on'][1])))})",
           f"{len(digests)}/10 distinct", "PASS" if sc_ok else "FAIL", F_SCRIPT[w]]
    rows.append(row)
    print("\t".join(row), flush=True)
with open(os.path.join(out, "matrix.tsv"), "w") as f:
    f.write("workload\tR\tD faults off\tD faults on\tseeds\toplog self-check\tF (script in this run)\n")
    for r in rows:
        f.write("\t".join(r) + "\n")
sys.exit(0 if ok_all else 1)
