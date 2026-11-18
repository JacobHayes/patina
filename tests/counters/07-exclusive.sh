# arm64 exclusive accesses under counters (every one emulated). A load- or store-exclusive that
# faults raises the instruction's own fault, SIGSEGV with the program counter still at it (the
# handler maps the page, returns, and the access runs again, still emulated, so the pair stays
# on one monitor and the retry loop ends): it prints what it prints natively. Every exclusive
# form at aligned and unaligned offsets (`align`) raises what it raises natively, line for line
# (signal, si_code, si_addr). A program with more exclusive instructions than one process's patch
# table holds stops `unsupported`, stop `capacity`, instead of leaving any of them native.
# SKIP without CAP_PERFMON or a supported CPU.
#@ tier=area budget=60 slots=2 arch=aarch64
. "$(dirname "$0")/lib.inc"
python3 -I - <<'PY'
import glob, os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import *
from concurrent.futures import ThreadPoolExecutor
P = ppatina(required=False)
G = GU + "/counters/excl"
# A livelocked retry loop ends at the wall-time bound, not the script's.
opts = PMU + ["timeout=120"]
def one(mode):
    exe = "excl-many" if mode == "many" else "excl"
    return mode, run(P, f"{RUNS}/{mode}", 1, GU, opts, [f"/guest/counters/{exe}", mode])
def lines(text):
    return [l.strip() for l in text.splitlines() if l.strip()]
fail = []
with ThreadPoolExecutor(3) as ex:
    for mode, o in ex.map(one, ["map", "align", "many"]):
        st = o.get("counters", {}).get("pmu", {})
        print(f"{mode}: {o['outcome']} {o.get('stop')} {o['message'][:100]!r}, {o['_last']!r}, preemptions {st.get('preempts')}")
        if mode == "many":
            if (o["outcome"], o.get("stop")) != ("unsupported", "capacity"):
                fail.append(f"many: {o['outcome']} {o.get('stop')}, want unsupported capacity")
            continue
        if mode == "align":
            want = lines(subprocess.run([G, mode], capture_output=True, text=True, check=True).stdout)
            got = []
            for f in glob.glob(f"{RUNS}/align/inc-*/stdout"):
                got = lines(open(f, errors="replace").read())
            if o["outcome"] != "ok" or not want or want[-1] != "align: done":
                fail.append(f"align: {o['outcome']} {o['message'][:80]}, natively {want[-1:]!r}")
            # The comparison means something only if the accesses were emulated.
            sites = o.get("counters", {}).get("insn", {}).get("patched_sites", {}).get("exclusive", 0)
            if sites < 27:
                fail.append(f"align: {sites} exclusive sites patched, want one per form (27) or more")
            for i, (w, g) in enumerate(zip(want, got)):
                if w != g:
                    fail.append(f"align line {i + 1}: {g!r}, natively {w!r}")
            if len(want) != len(got):
                fail.append(f"align: {len(got)} lines, natively {len(want)}")
            continue
        want = native([G, mode])
        if o["outcome"] != "ok":
            fail.append(f"{mode}: {o['outcome']} {o['message'][:80]}")
        elif o["_last"] != want:
            fail.append(f"{mode}: {o['_last']!r}, natively {want!r}")
if fail: die("; ".join(fail))
PY
