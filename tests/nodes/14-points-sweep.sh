# 14. Nodes: crash points, fuller (tests/guests/nodes/ack2.py, as 13-points). A `--branch` sweep
# over four seeds of `early` finds the lost acknowledged put on b in each seed and in b's
# children only, and the correct store is ok at every point of every node. A run crashing at
# per-mille chance at both nodes' points is identical under verify --vary, replays identically,
# and passes the operation-log self-check of every node disk (`log ops --check`). `minimize`
# reduces a planted failure (crashes at both nodes' points, net delays and duplicates, disk
# delays) to the one crash of b's that loses the put, `machine-at:N@b`, and nothing else. A
# node with `faults = false` is left out of `--crash machine` given without a scope.
#@ tier=area,release budget=120 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/14-points-sweep; mkdir -p "$o"
for v in ok early; do
    rm -f "$o/$v.toml"
    conf "$o/$v.toml" a python3 /guest/ack2.py a
    if [ $v = ok ]; then conf "$o/$v.toml" b python3 /guest/ack2.py b; else conf "$o/$v.toml" b python3 /guest/ack2.py b early; fi
done
D="python3 /guest/ack2.py driver 4"
sw() { rm -rf "${o:?}/sw-$1"; st=0; timeout 600 "$PATINA" sweep --seeds 1..4 --branch --crash machine -j 6 --keep "$2" --out "$o/sw-$1" \
    --config "$o/$1.toml" --mount "$PATINA_GUESTS":/guest:copy -- $D >"$o/sw-$1.txt" 2>&1 || st=$?; }
sw early fail
[ "$st" = 1 ] || die "branch sweep of early: exit $st: $(tail -5 "$o/sw-early.txt")"
python3 -I - "$o/sw-early" <<'PY' || die "branch sweep of early"
import json, os, sys
rep = json.load(open(os.path.join(sys.argv[1], "report.json")))
br = rep["branch"]
assert br["tried"] == br["points"], br
fails = [r for g in rep["groups"] for r in g["runs"]]
assert all("lost on b" in g["signature"] for g in rep["groups"]), [g["signature"] for g in rep["groups"]]
assert {r["node"] for r in fails} == {"b"}, {r["node"] for r in fails}
assert {r["seed"] for r in fails} == {1, 2, 3, 4}, {r["seed"] for r in fails}
print("early: %d of %d points fail, in every seed, on b only" % (len(fails), br["points"]))
PY
sw ok none
[ "$st" = 0 ] || die "branch sweep of ok: exit $st: $(tail -5 "$o/sw-ok.txt")"
grep '^crash points:' "$o/sw-ok.txt"
# Per-mille crashes at both nodes' points: determinism and the self-check of each node disk.
P="--config $o/ok.toml --crash machine:60"
s=$((RANDOM % 100 + 1))
verify_ok "$o/verify" $s 3 $P -- $D
run_ok "$o/p" $s $P -- $D
python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); assert sum(len(n.get("downs", [])) for n in r["nodes"]["list"]) > 0' "$o/p/result.json" \
    || die "seed $s: no node crashed at a point"
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
python3 -I - "$o/m" <<'PY' || die "minimize: exit $st: $(tail -3 "$o/min.err")"
import json, os, re, sys
d = sys.argv[1]
run = json.load(open(os.path.join(d, "minimized", "run.json")))
c = run["config"]
assert re.fullmatch(r"machine-at:\d+@b", c.get("crash") or ""), c.get("crash")
assert not c.get("faults") and not c.get("faults-preset"), c.get("faults")
print("minimize: reduced to --crash %s alone" % c["crash"])
PY
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
