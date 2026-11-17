# Evidence (docs/EVIDENCE.md, "Crash-point enumeration"): `patina sweep --branch` on the
# fjall harness (debug) and acklog-c against plain sweeps, each sweep once at -j 6:
# - F2 and F6 under --branch (seeds 1..3, 200 s), and F6 with manual-flush at every evaluation;
# - the plain acceptance sweeps for F1, F3, F4 (one sweep) and F5, and acklog-c;
# - F1, acklog-c, F3 and F4 under --branch;
# - the cost of the F2 branch sweep: crash points per seed, child wall_ms by the point's
#   position, the share of a child's time that is the prefix it shares with its base, and the
#   share of children whose post-crash tree repeats an earlier child's of the same seed.
# Every line gives the runs with the finding, the CPU-seconds (sum of wall_ms) and the rate.
#@ tier=evidence budget=1500 slots=6 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
: "${PATINA_GUESTS:?}"
H=/guest/fjall-harness-debug
FJ="--mount $W/fjall-harness:/guest:copy"
AK="--mount $PATINA_GUESTS/examples:/guest:copy"
F3="--env FJ_N=1000 --buggify --env FJ_LOG=1 --env FJ_WIPE_PARTIAL=1 --time-limit 400 --fault fs-error-permille=3"
# sw NAME ARGS...: one sweep into $RUNS/NAME (its text in NAME.txt).
sw() {
    n=$1; shift
    t0=$(date +%s)
    # shellcheck disable=SC2086
    "$PATINA" sweep -j 6 --keep fail --out "$RUNS/$n" "$@" >"$RUNS/$n.txt" 2>&1 || true
    [ -f "$RUNS/$n/report.json" ] || die "$n: no report ($(tail -3 "$RUNS/$n.txt"))"
    echo "$n: $(( $(date +%s) - t0 )) s wall: patina sweep -j 6 $*" | sed "s|$W|W|g; s|$PATINA_GUESTS|G|g"
}
# stats NAME REGEX: runs whose signature or message matches, CPU-seconds, rate.
stats() { python3 -I - "$RUNS/$1" "$2" <<'PY'
import json, os, re, sys
d, rx = sys.argv[1], re.compile(sys.argv[2])
rows = []
for root, dirs, files in os.walk(d):
    dirs[:] = [x for x in dirs if not x.startswith(".") and not x.startswith("inc-")]
    if "result.json" in files:
        r = json.load(open(os.path.join(root, "result.json")))
        rows.append((os.path.basename(root), r))
hit = [n for n, r in rows if rx.search("%s %s" % (r.get("signature") or "", r.get("message") or ""))]
cpu = sum(r.get("wall_ms", 0) for _, r in rows) / 1000
rep = json.load(open(os.path.join(d, "report.json")))
b = rep.get("branch")
print("  %s: %d of %d runs match /%s/, %.0f CPU-s, %.2e per CPU-s%s%s; groups: %s" % (
    os.path.basename(d), len(hit), len(rows), sys.argv[2], cpu, len(hit) / cpu if cpu else 0,
    "; points %d of %d tried" % (b["tried"], b["points"]) if b else "",
    "; stopped: %s" % rep["sweep"]["stopped"] if rep.get("sweep", {}).get("stopped") else "",
    ["%s %d" % (g["signature"][:50], g["count"]) for g in rep["groups"]]))
PY
}

echo "== E1: F2 and F6 under --branch"
sw f2 --seeds 1..3 --branch --crash machine --buggify --env FJ_N=2000 --budget 200 $FJ -- $H
stats f2 'journal/entry.rs'
stats f2 'batch-atomic-across-keyspaces'
stats f2 'open-after-crash'
sw f6 --seeds 1..3 --branch --crash machine --buggify --env FJ_N=2000 --fault point:manual-flush=1000 --budget 200 $FJ -- $H
stats f6 'batch-atomic-across-keyspaces'
stats f6 'journal/entry.rs'

echo "== E2: plain sweeps (the acceptance commands)"
sw f1p --seeds 1..300 --crash machine:3 $FJ -- $H
stats f1p 'open-after-crash'
sw f3p --seeds 1..600 $F3 --crash machine:2 $FJ -- $H
stats f3p 'liveness|parked'
sw f4p --seeds 1..1000 --fault fsync-error-at=1..100 --crash machine $FJ -- $H
stats f4p 'batch-atomic-across-keyspaces'
sw f5p --seeds 1..100 --fault fs-short-permille=20 $FJ -- $H
stats f5p 'iterate-failed|reopen-failed'
sw akp --seeds 1..20 --crash machine $AK -- /guest/acklog
stats akp 'acked-records-kept'

echo "== E2: the same findings under --branch"
sw f1b --seeds 1..3 --branch --crash machine --max-findings 1 $FJ -- $H
stats f1b 'open-after-crash'
sw akb --seeds 1 --branch --crash machine $AK -- /guest/acklog
stats akb 'acked-records-kept'
sw f3b --seeds 1..3 --branch --crash machine $F3 --budget 120 $FJ -- $H
stats f3b 'liveness|parked'
sw f4b --seeds 1..10 --branch --crash machine --fault fsync-error-at=1..100 --budget 120 $FJ -- $H
stats f4b 'batch-atomic-across-keyspaces'

echo "== E4: cost of the F2 branch sweep"
for s in 1 2 3; do
    "$PATINA" run --seed $s --crash machine:0 --buggify --env FJ_N=2000 --out "$RUNS/base-$s" $FJ -- $H >/dev/null 2>&1 || true
    "$PATINA" log dump "$RUNS/base-$s/inc-0/boundary.log" | tail -1 | sed -n 's/^seq=\([0-9]*\) .*/\1/p' >"$RUNS/base-$s.last"
done
python3 -I - "$RUNS" <<'PY'
import json, os, re, statistics, sys
R = sys.argv[1]
d = os.path.join(R, "f2")
rep = json.load(open(os.path.join(d, "report.json")))
pts = {x["seed"]: x["points"] for x in rep["branch"]["seeds"]}
print("  crash points per seed: %s (min %d, median %d, max %d)" % (
    pts, min(pts.values()), statistics.median(pts.values()), max(pts.values())))
kids, base = [], {}
for name in os.listdir(d):
    m = re.fullmatch(r"seed-(\d+)(?:@(\d+))?", name)
    if not m or not os.path.isfile(os.path.join(d, name, "result.json")):
        continue
    r = json.load(open(os.path.join(d, name, "result.json")))
    s = int(m.group(1))
    if m.group(2) is None:
        base[s] = r
    else:
        kids.append((int(m.group(2)), s, r))
kids.sort()
ms = [r["wall_ms"] for _, _, r in kids]
print("  children: %d, wall_ms median %d" % (len(kids), statistics.median(ms)))
for q in range(4):
    sel = [r["wall_ms"] for p, s, r in kids if q * pts[s] <= 4 * (p - 1) < (q + 1) * pts[s]]
    if sel:
        print("    quartile %d of the point's position: %d children, median %d ms" % (q + 1, len(sel), statistics.median(sel)))
share = []
for p, s, r in kids:
    last = int(open(os.path.join(R, "base-%d.last" % s)).read() or 0)
    if r["crashes"] and last and r["wall_ms"]:
        share.append(min(1.0, base[s]["wall_ms"] * r["crashes"][0]["seq"] / last / r["wall_ms"]))
print("  prefix share of a child's time: median %.2f, mean %.2f" % (statistics.median(share), statistics.mean(share)))
for s in sorted(pts):
    trees = [r["crashes"][0]["tree_digest"] for p, x, r in kids if x == s and r["crashes"]]
    if trees:
        print("  seed %d: %d of %d children repeat a post-crash tree (%.0f%%)" % (s, len(trees) - len(set(trees)), len(trees), 100 * (len(trees) - len(set(trees))) / len(trees)))
f2 = [(p, s, r) for p, s, r in kids if "journal/entry.rs" in (r.get("signature") or "")]
cpu = 0
for p, s, r in kids:
    cpu += r["wall_ms"]
    if (p, s, r) == (f2[0] if f2 else None):
        print("  first F2 in sweep order: seed %d@%d after %.0f CPU-s of children (bases %.1f)" % (s, p, cpu / 1000, sum(b["wall_ms"] for b in base.values()) / 1000))
        break
for s in sorted(pts):
    mine = [(p, r) for p, x, r in kids if x == s]
    hit = next((p for p, r in mine if "journal/entry.rs" in (r.get("signature") or "")), None)
    if hit:
        print("  seed %d: first F2 at point %d, %.0f CPU-s of its own children up to it" % (s, hit, sum(r["wall_ms"] for p, r in mine if p <= hit) / 1000))
PY
rm -rf "$RUNS"/base-*
