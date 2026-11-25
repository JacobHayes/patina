"""The tracker self-check (`patina inspect check-ops`) on W1-W9, seeds 1-3, faults off and on.
Usage: oplog.py OUTDIR (PATINA, PATINA_GUESTS set). Prints one line per run."""
import os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from workloads import WL, ORDER
PATINA = os.environ["PATINA"]; O = sys.argv[1]
for w in ORDER:
    g, argv, faults, extra = WL[w]
    for key, opts in (("off", extra), ("on", extra + faults)):
        for s in (1, 2, 3):
            d = f"{O}/{w}-{key}-{s}"
            subprocess.run(["rm", "-rf", d])
            r = subprocess.run([PATINA, "run", "--seed", str(s), "--out", d, "--mount", g + ":/guest:copy", *opts, "--", *argv], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
            c = subprocess.run([PATINA, "inspect", "check-ops", d], capture_output=True, text=True, timeout=900)
            last = (c.stdout + c.stderr).strip().splitlines()[-1:] 
            print(w, key, s, "check-exit", c.returncode, last, flush=True)
            subprocess.run(["sh", "-c", f"find {d} -name boundary.log -delete"])
