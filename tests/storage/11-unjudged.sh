# 11. The harness never judges an injected fault as a finding. W9's settings with a higher
# error rate (--crash machine:5, fs-error-permille=20), seeds 1-40: in every run whose guest
# reports the errno of the last injected fault, the guest must call it UNJUDGED (exit 0),
# never an INVARIANT or a panic. At least one run must reach that case.
#@ tier=quick budget=15 slots=4 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
sweep unjudged fjall-harness 1-40 -- --crash machine:5 --fault fs-error-permille=20 -- /guest/fjall-harness-release >/dev/null
python3 -I - "$RUNS/unjudged/outcomes" <<'PY'
import errno, glob, json, os, re, sys
seen, bad = 0, []
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.json"))):
    r = json.load(open(p))
    last = (r.get("faults") or {}).get("recent") or [{}]
    e = last[-1].get("errno")
    if last[-1].get("fault") != "fs-error" or not hasattr(errno, e or ""):
        continue
    err = open(p[:-5] + ".err", errors="replace").read()
    if not re.search(r"(code: |os error )%d\b" % getattr(errno, e), err):
        continue
    seen += 1
    if r["outcome"] != "ok":
        bad.append("seed %s: injected %s on %s, judged: %s" % (os.path.basename(p)[:-5], e, last[-1].get("call"), r["message"]))
print("runs whose guest saw the last injected errno: %d, judged as findings: %d" % (seen, len(bad)))
for b in bad:
    print("  " + b)
if not seen:
    sys.exit("FAIL: no run reached an injected errno (vacuous)")
if bad:
    sys.exit("FAIL: an injected fault was judged a finding")
PY
