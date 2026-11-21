# 14. Nodes: crash points, fuller (tests/guests/nodes/ack2.py, as 13-points). A `--branch` sweep
# over four seeds of `early` (two in the release tier) finds the lost acknowledged put on b in
# each seed and in b's children only, and the correct store is ok at every point of every node.
# A run crashing at per-mille chance at both nodes' points is identical under verify --vary,
# replays identically, and passes the operation-log self-check of every node disk (`log ops
# --check`). `minimize`
# reduces a planted failure (crashes at both nodes' points, net delays and duplicates, disk
# delays) to what it needs: a crash kept at points was tried as one node's crash alone, one
# kept at a point is b's (`machine-at:N@b`), and every fault setting left was tried without
# and no longer failed. Which settings a failure needs depends on its seed, and the failing
# seed found depends on the host: on the reference host it is the crash alone (docs/GUIDE.md).
# In the area, a failing seed is reduced to one of b's later crashes alone, at its place in a
# first boot (the first crash alone, tried first, did not fail).
# A node with `faults = false` is left out of `--crash machine` given without a scope.
#@ tier=area,release budget=120 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/14-points-sweep; mkdir -p "$o"
for v in ok early; do
    rm -f "$o/$v.toml"
    conf "$o/$v.toml" a python3 /guest/ack2.py a
    if [ $v = ok ]; then conf "$o/$v.toml" b python3 /guest/ack2.py b; else conf "$o/$v.toml" b python3 /guest/ack2.py b early; fi
done
D="python3 /guest/ack2.py driver 4"
S=4; [ "${CHECK_TIER:-}" != release ] || S=2
sw() { rm -rf "${o:?}/sw-$1"; st=0; timeout 600 "$PATINA" sweep --seeds 1..$S --branch --crash machine -j 6 --keep "$2" --out "$o/sw-$1" \
    --config "$o/$1.toml" --mount "$PATINA_GUESTS":/guest:copy -- $D >"$o/sw-$1.txt" 2>&1 || st=$?; }
sw early fail
[ "$st" = 1 ] || die "branch sweep of early: exit $st: $(tail -5 "$o/sw-early.txt")"
python3 -I - "$o/sw-early" "$S" <<'PY' || die "branch sweep of early"
import json, os, sys
rep = json.load(open(os.path.join(sys.argv[1], "report.json")))
br = rep["branch"]
assert br["tried"] == br["points"], br
fails = [r for g in rep["groups"] for r in g["runs"]]
assert all("lost on b" in g["signature"] for g in rep["groups"]), [g["signature"] for g in rep["groups"]]
assert {r["node"] for r in fails} == {"b"}, {r["node"] for r in fails}
assert {r["seed"] for r in fails} == set(range(1, int(sys.argv[2]) + 1)), {r["seed"] for r in fails}
print("early: %d of %d points fail, in every seed, on b only" % (len(fails), br["points"]))
PY
sw ok fail
[ "$st" = 0 ] || die "branch sweep of ok: exit $st: $(tail -5 "$o/sw-ok.txt")"
grep '^crash points:' "$o/sw-ok.txt"
# Per-mille crashes at both nodes' points: determinism and the self-check of each node disk.
# A run has about 19 points per node, so about one seed in ten crashes neither node: the first
# seed from a random start that crashes one.
P="--config $o/ok.toml --crash machine:60"
s0=$((RANDOM % 100 + 1)); s=""
for t in $(seq "$s0" $((s0 + 9))); do
    run_ok "$o/p" "$t" $P -- $D
    python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(sum(len(n.get("downs", [])) for n in r["nodes"]["list"]) == 0)' \
        "$o/p/result.json" && { s=$t; break; }
done
[ -n "$s" ] || die "seeds $s0..$((s0 + 9)): no node crashed at a point"
verify_ok "$o/verify" "$s" 3 $P -- $D
"$PATINA" log ops --check "$o/p" >"$o/check.txt" || die "log ops --check: $(cat "$o/check.txt")"
for n in a b; do grep -q "/node/$n/inc-0: ok " "$o/check.txt" || die "log ops --check: no disk of $n: $(cat "$o/check.txt")"; done
st=0; timeout 300 "$PATINA" replay "$o/p" >"$o/replay.txt" 2>&1 || st=$?
grep -q '^identical' "$o/replay.txt" || die "replay: exit $st: $(head -3 "$o/replay.txt")"
echo "seed $s: replay identical, every node disk passes log ops --check"
# Minimize a planted multi-fault failure: search seeds for one that fails.
F="--config $o/early.toml --crash machine:60 --fault net-delay-ms=0..20 --fault net-dup-permille=10 --fault fs-delay-permille=20"
found=""
for s in $(seq 1 20); do
    [ "$(run "$o/m" $s $F -- $D)" = failure ] && { found=$s; break; }
done
[ -n "$found" ] || die "no seed of 1..20 fails with $F"
st=0; timeout 900 "$PATINA" minimize "$o/m" --format json >"$o/min.json" 2>"$o/min.err" || st=$?
python3 -I - "$o/m" "$o/min.json" <<'PY' || die "minimize: exit $st: $(tail -3 "$o/min.err")"
import json, os, re, sys
d = sys.argv[1]
m = json.load(open(sys.argv[2]))
assert m["reduced"] and m["runs"] < m["max_runs"], m
run = json.load(open(os.path.join(d, "minimized", "run.json")))
c = run["config"]
crash, faults = c.get("crash") or "", c.get("faults") or []
assert not c.get("faults-preset"), c
if "-at:" in crash:
    assert re.fullmatch(r"machine-at:\d+@b", crash), crash
else:
    # Each node's crash alone was tried, and none failed the same way.
    t = [x for x in m["tries"] if "-> machine-at:" in x["change"]]
    assert crash.startswith("machine:") and t and not any(x["still_fails"] for x in t), (crash, m["tries"])
for f in faults:
    # The last try without the setting no longer failed.
    t = [x for x in m["tries"] if x["change"].startswith("without %s=" % f.split("=")[0])]
    assert t and not t[-1]["still_fails"], (f, m["tries"])
print("minimize: reduced to %s (from %s)" % (m["to"], m["from"]))
PY
# In the area: a failure that a node's first crash alone does not give is reduced to one of its
# later crashes alone. Among the first failing seeds, one where minimize's crash alone that kept
# the failure is not the first it tried for that node.
if [ "${CHECK_TIER:-}" = area ]; then
    later=""; tried=0
    for s in $(seq 1 100); do
        [ "$(run "$o/l" $s $F -- $D)" = failure ] || continue
        tried=$((tried + 1))
        st=0; timeout 300 "$PATINA" minimize "$o/l" --format json >"$o/l.json" 2>"$o/l.err" || st=$?
        [ "$st" = 0 ] || die "minimize seed $s: exit $st: $(tail -3 "$o/l.err")"
        if python3 -I - "$o/l.json" <<'PY'
import json, re, sys
m = json.load(open(sys.argv[1]))
seen = {}
for t in m["tries"]:
    x = re.search(r"-> machine-at:\d+@(\S+)$", t["change"])
    if x:
        seen[x[1]] = seen.get(x[1], 0) + 1
        if t["still_fails"]:
            sys.exit(0 if seen[x[1]] > 1 else 1)
sys.exit(1)
PY
        then later="seed $s: $(python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); print("%s, from %s" % (m["to"], m["from"]))' "$o/l.json")"; break; fi
        [ "$tried" -lt 12 ] || break
    done
    [ -n "$later" ] || die "no failing seed of the first $tried reduced to a node's later crash alone"
    echo "minimize: a later crash alone: $later"
fi
# faults = false: an unscoped --crash leaves the node out.
{ cat "$o/ok.toml"; printf 'faults = false\n'; } >"$o/free.toml"
run_ok "$o/free" 1 --config "$o/free.toml" --crash machine:300 -- $D
python3 -I - "$o/free/result.json" <<'PY' || die "faults = false"
import json, sys
r = json.load(open(sys.argv[1]))
a, b = r["nodes"]["list"][1], r["nodes"]["list"][2]
assert a.get("downs") and not b.get("downs") and "crash_points" not in b, (a, b)
print("faults = false: a crashed %d times, b none" % len(a["downs"]))
PY
