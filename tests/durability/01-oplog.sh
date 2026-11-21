# The tracker self-check (`patina log ops --check`: replay of the whole operation log = the exported
# live tree, every incarnation) on W1-W9, seed 1, with each workload's fault configuration
# (tests/durability/bench/workloads.py), 4 at a time. Regression for the unix-socket bind bug: W2
# (tokio-mt local binds unix sockets) failed the check on every run before the fix.
#@ tier=quick budget=30 slots=2
: "${PATINA:?}" "${RUNS:?}" "${PATINA_WORKLOADS:?}" "${PATINA_GUESTS:?}"
here=$(cd "$(dirname "$0")" && pwd)
python3 -I - "$here/bench" "$RUNS" <<'PY'
import concurrent.futures as cf, os, subprocess, sys
sys.path.insert(0, sys.argv[1])
from workloads import WL, ORDER
PATINA = os.environ["PATINA"]; O = sys.argv[2]
def one(w):
    g, argv, faults, extra = WL[w]
    d = f"{O}/{w}"
    subprocess.run([PATINA, "run", "--seed", "1", "--out", d, "--mount", g + ":/guest:copy", *extra, *faults, "--", *argv],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
    c = subprocess.run([PATINA, "log", "ops", "--check", d], capture_output=True, text=True, timeout=300)
    subprocess.run(["rm", "-rf", d])
    return w, c.returncode, ((c.stdout + c.stderr).strip().splitlines() or [""])[-1]
bad = 0
with cf.ThreadPoolExecutor(4) as ex:
    for w, rc, last in ex.map(one, ORDER):
        print(f"{w}: oplog check exit {rc}: {last}")
        bad += rc != 0
sys.exit(1 if bad else 0)
PY
