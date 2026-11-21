# Evidence (compute points): a timer that falls due inside rebuilt code
# stops it at the exact event. Each `deadline` guest (a 50 ms timer, a loop with no system
# call), seeds 1-20 at the seed's gap and at compute-gap=0: all ok, the loop's virtual time in
# range, and for guests that report it the handler within ten trap charges of 50 ms; then one
# seed under verify --runs 20 --vary cpu,load,aslr,sandbox: one digest.
# Languages add their guest to GUESTS: (name, program and arguments under /guest/compute).
#@ tier=evidence budget=300 slots=6
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
OUT=$RUNS/evidence-deadline python3 -I - <<'PY'
import json, os, re, subprocess
from concurrent.futures import ThreadPoolExecutor

P, GU, OUT = os.environ["PATINA"], os.environ["PATINA_GUESTS"], os.environ["OUT"]
N = 20
GUESTS = [("C", ["deadline", "deadline", "50"]), ("Go", ["go-deadline", "134217728"]), ("Rust", ["rs-deadline"])]
COLS = [("seed's gap", []), ("gap 0", ["--fault", "compute-gap=0"])]
WANT = 50_000_000


def run(job):
    (gn, argv), (cn, opts), s = job
    out = os.path.join(OUT, f"{gn}-{cn.replace(' ', '').replace(chr(39), '')}-{s}")
    subprocess.run(["rm", "-rf", out])
    subprocess.run([P, "run", "--seed", str(s), "--out", out, "--mount", GU + ":/guest:copy", "--timeout", "120",
                    *opts, "--", f"/guest/compute/{argv[0]}", *argv[1:]],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
    with open(os.path.join(out, "result.json")) as f:
        r = json.load(f)
    with open(os.path.join(out, "inc-0", "stdout")) as f:
        text = f.read()
    subprocess.run(["rm", "-rf", out])  # judged: keep nothing
    return job, r, text


jobs = [(g, c, s) for g in GUESTS for c in COLS for s in range(1, N + 1)]
with ThreadPoolExecutor(6) as ex:
    res = list(ex.map(run, jobs))
for g in GUESTS:
    for c in COLS:
        rows = [(j[2], r, t) for j, r, t in res if j[0] == g and j[1] == c]
        ok = [s for s, r, _ in rows if r["outcome"] == "ok"]
        late = []
        for s, _, t in rows:
            m = re.search(r"handler_ns=(\d+)", t)
            if m:
                late.append(int(m.group(1)) - WANT)
        bad = [x for x in late if not 0 <= x <= 10_000]
        print(f"{g[0]:<4} {c[0]:<11} ok {len(ok)}/{N}; handler after the 50 ms: "
              f"{min(late) if late else '-'}..{max(late) if late else '-'} ns, {len(bad)} outside 0..10000; "
              f"deadline stops {sorted({r.get('compute', {}).get('deadline_stops') for _, r, _ in rows})}", flush=True)
    out = os.path.join(OUT, f"{g[0]}-verify")
    subprocess.run(["rm", "-rf", out])
    v = subprocess.run([P, "verify", "--runs", "20", "--vary", "cpu,load,aslr,sandbox", "--seed", "1", "--out", out,
                        "--mount", GU + ":/guest:copy", "--", f"/guest/compute/{g[1][0]}", *g[1][1:]],
                       capture_output=True, text=True, timeout=1200)
    line = next((l for l in v.stdout.splitlines() if l.startswith(("identical", "divergence"))), v.stdout.strip()[-200:])
    print(f"{g[0]:<4} seed 1, verify --runs 20 --vary cpu,load,aslr,sandbox: {line}", flush=True)
    if line.startswith("identical"):
        subprocess.run(["rm", "-rf", out])
PY
