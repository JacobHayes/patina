# 13. Machines: a machine crash at its crash points (tests/guests/machines/ack2.py: a forwards
# each put to b and acknowledges once b answers; b answers after its fsync, or with `early`
# before it). `--fault crash-at=N@a` in the middle of a's points crashes a's machine there:
# one crash event naming a and the point, a's crashed disk kept as post-crash with what it lost
# counted, a restarted, and b untouched (one boot, no post-crash, every put on its disk). A
# `--crash-points` sweep crashes each point of each machine in turn: on `early` it finds the lost
# acknowledged put on b, in children of b only, with b's crash losing it on b's disk, and the
# report's group names b's crash points; the correct store is ok at every point of both machines;
# a child's rerun line gives its digest again. `--crash-points=N` runs a sample with each machine in it
# and says how many of how many it tried; `[sweep] crash-pairs` crashes the other machine at its next
# point after each first crash (of a run of two puts), the correct store ok at each pair, a pair's rerun line giving
# its digest again. One seed, a few puts. The quick tier stops before the sample and the pairs
# (the area tier runs them): about 12 s on the arm64 runner.
#@ tier=quick budget=30 slots=2.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/13-points; mkdir -p "$o"
for v in ok early; do
    rm -f "$o/$v.toml"
    printf '[run]\nsetup = "mark"\n' >"$o/$v.toml"  # main marks setup-complete
    conf "$o/$v.toml" a python3 /guest/ack2.py a
    if [ $v = ok ]; then conf "$o/$v.toml" b python3 /guest/ack2.py b; else conf "$o/$v.toml" b python3 /guest/ack2.py b early; fi
    driver "$o/$v.toml"
done
D="python3 /guest/ack2.py main 3"
s=1
# a's points in a run that counts them and never crashes; then a crash at the middle one.
run_ok "$o/base" $s --config "$o/ok.toml" --fault crash-permille=0@a -- $D
n=$(field "$o/base/result.json" machines.list.1.crash_points.0)
[ "$n" -ge 2 ] || die "a counted $n crash points"
p=$((n / 2))
run_ok "$o/at" $s --config "$o/ok.toml" --fault crash-at=$p@a -- $D
"$PATINA" log events "$o/at" --types crash | grep '"type":"crash"' >"$o/at.crash" || die "no crash event"
[ "$(wc -l <"$o/at.crash")" = 1 ] || die "crash events: $(cat "$o/at.crash")"
python3 -I - "$o/at" "$p" <<'PY' || die "crash at point $p of a"
import json, os, sys
d, p = sys.argv[1], int(sys.argv[2])
r = json.load(open(os.path.join(d, "result.json")))
a, b = r["machines"]["list"][1], r["machines"]["list"][2]
e = [json.loads(l) for l in open(d + ".crash")][0]
assert (e["machine"], e["kind"], e["point"]) == ("a", "machine", p), e
down = a["downs"][0]
assert down["point"] == p and a["boots"] == 2, a
assert set(down["lost"]) >= {"missing", "changed", "back"}, down
assert os.path.isdir(os.path.join(d, "machine/a/boot-1/post-crash")), "no post-crash for a"
assert b["boots"] == 1 and not b.get("downs"), b
assert not os.path.exists(os.path.join(d, "machine/b/boot-1/post-crash")), "b has a post-crash"
assert not os.path.exists(os.path.join(d, "machine/b/boot-2")), "b booted again"
out = open(os.path.join(d, "boot-1/stdout")).read()
assert "b holds 3" in out, out
PY
echo "crash at point $p of a's $n: a down once, b untouched"
# A process kill at the same point: a's processes killed there and restarted on its disk as it
# was (no crash of its disk), b untouched.
run_ok "$o/pk" $s --config "$o/ok.toml" --faults kill@a --fault crash-at=$p@a -- $D
python3 -I - "$o/pk" "$p" <<'PY' || die "process kill at point $p of a"
import json, os, sys
d, p = sys.argv[1], int(sys.argv[2])
r = json.load(open(os.path.join(d, "result.json")))
a, b = r["machines"]["list"][1], r["machines"]["list"][2]
down = a["downs"][0]
assert (down["how"], down["point"], a["boots"]) == ("killed", p, 2), a
assert "lost" not in down and not os.path.exists(os.path.join(d, "machine/a/boot-1/post-crash")), down
assert b["boots"] == 1 and not b.get("downs"), b
assert r["self_check"]["verdict"] == "pass", r["self_check"]
PY
echo "process kill at point $p of a: a killed there once and restarted on its disk, b untouched"
# Branch over every point of each machine.
# sw NAME KEEP: KEEP none is the test input PATINA_TEST_KEEP_NONE.
sw() { rm -rf "${o:?}/sw-$1"; st=0; k=$2; env $([ "$k" = none ] && echo PATINA_TEST_KEEP_NONE=1) timeout 300 "$PATINA" sweep --seeds $s --crash-points --faults crash -j 4 --keep "${k/none/fail}" --out "$o/sw-$1" \
    --config "$o/$1.toml" --mount "$PATINA_GUESTS":/guest:copy -- $D >"$o/sw-$1.txt" 2>&1 || st=$?; }
sw early fail
[ "$st" = 1 ] || die "branch sweep of early: exit $st: $(tail -5 "$o/sw-early.txt")"
grep -q '^  machines: a down in 0, b down in [1-9]' "$o/sw-early.txt" || die "group's machines line: $(cat "$o/sw-early.txt")"
# Every name the sweep wrote is one a CI artifact upload takes (no ", :, <, >, |, *, ?).
bad=$(find "$o/sw-early" -name '*[":<>|*?]*' | head -3)
[ -z "$bad" ] || die "names an artifact upload refuses: $bad"
python3 -I - "$o/sw-early" <<'PY' || die "branch sweep of early"
import json, os, sys
d = sys.argv[1]
rep = json.load(open(os.path.join(d, "report.json")))
br = rep["crash_points"]
assert br["tried"] == br["points"] and [x["machine"] for x in br["machines"]] == ["a", "b"], br
assert all(x["points"] > 0 and x["tried"] == x["points"] for x in br["machines"]), br
assert len(rep["groups"]) == 1, [g["signature"] for g in rep["groups"]]
g = rep["groups"][0]
assert "lost on b" in g["signature"], g["signature"]
assert all(x["machine"] == "b" for x in g["runs"]), g["runs"]
lost = 0
for x in g["runs"]:
    r = json.load(open(os.path.join(x["dir"], "result.json")))
    b = r["machines"]["list"][2]
    assert b["downs"][0]["point"] == x["point"], (x, b["downs"])
    l = b["downs"][0]["lost"]
    # The sweep keeps a failure's post-crash tree packed.
    lost += l["missing"] + l["changed"] > 0 and os.path.isfile(os.path.join(x["dir"], "machine/b/boot-1/post-crash.tree.zst"))
assert lost > 0, "no failing child lost anything on b's disk"
print("early: %d of %d points (a %d, b %d) fail, all on b" % (g["count"], br["points"], *[x["points"] for x in br["machines"]]))
PY
sw ok none
[ "$st" = 0 ] || die "branch sweep of ok: exit $st: $(tail -5 "$o/sw-ok.txt")"
python3 -I - "$o/sw-ok" <<'PY' || die "branch sweep of ok"
import json, os, sys
rep = json.load(open(os.path.join(sys.argv[1], "report.json")))
br = rep["crash_points"]
assert rep["groups"] == [] and rep["outcomes"] == {"ok": rep["runs"]}, rep["outcomes"]
assert br["tried"] == br["points"] and all(x["tried"] == x["points"] > 0 for x in br["machines"]), br
print("ok: ok at all %d points" % br["points"])
PY
# A failing child's rerun line reproduces it.
c=$(field "$o/sw-early/report.json" groups.0.first.dir)
st=0; timeout 120 "$PATINA" run --seed $s --config "$c/run.json" --out "$o/rerun" -- $D >/dev/null 2>&1 || st=$?
d1=$(field "$o/rerun/result.json" digest) d2=$(field "$c/result.json" digest)
[ "$d1" = "$d2" ] || die "rerun of $c: digest $d1, not $d2"
echo "rerun: same digest"
[ "${CHECK_TIER:-}" != quick ] || exit 0
# A sample: at most 4 children, both machines among them, and the report says how many of how many.
sw2() { n=$1; shift; rm -rf "${o:?}/$n"; st=0; PATINA_TEST_KEEP_NONE=1 timeout 300 "$PATINA" sweep --seeds $s --crash-points --faults crash -j 4 \
    --out "$o/$n" --config "$o/ok.toml" "$@" --mount "$PATINA_GUESTS":/guest:copy -- $D >"$o/$n.txt" 2>&1 || st=$?; }
sw2 max --crash-points=4
[ "$st" = 0 ] || die "--crash-points=N: exit $st: $(tail -5 "$o/max.txt")"
python3 -I - "$o/max/report.json" "$o/sw-ok/report.json" <<'PY' || die "--crash-points=4"
import json, sys
br, full = json.load(open(sys.argv[1]))["crash_points"], json.load(open(sys.argv[2]))["crash_points"]
assert br["tried"] == 4 and br["points"] == full["points"], (br, full)
assert all(x["tried"] > 0 for x in br["machines"]), br["machines"]
print("--crash-points=4: %d of %d tried (%s)" % (br["tried"], br["points"], ", ".join("%s %d" % (x["machine"], x["tried"]) for x in br["machines"])))
PY
grep -q "^crash points: 4 of " "$o/max.txt" || die "--crash-points=N: $(cat "$o/max.txt")"
# Pairs: after each first crash whose child ended ok, the other machine's next point; of a main
# of two puts (fewer points: the pairs are a second level of runs).
D="python3 /guest/ack2.py main 2"
{ cat "$o/ok.toml"; printf '[sweep]\ncrash-pairs = 1\n'; } >"$o/pairs.toml"
sw2 pairs --config "$o/pairs.toml"
[ "$st" = 0 ] || die "crash-pairs: exit $st: $(tail -5 "$o/pairs.txt")"
python3 -I - "$o/pairs/report.json" <<'PY' || die "crash-pairs 1"
import json, sys
rep = json.load(open(sys.argv[1]))
pr = rep["crash_points"]["pairs"]
assert pr["pairs"] > 0 and pr["tried"] == pr["pairs"] and rep["groups"] == [], rep["crash_points"]
print("crash-pairs 1: ok at all %d pairs" % pr["tried"])
PY
grep -q "^crash pairs: [1-9][0-9]* of " "$o/pairs.txt" || die "crash-pairs: $(cat "$o/pairs.txt")"
# A pair's rerun line reproduces it (its run.json names both crashes).
c=$(find "$o/pairs" -maxdepth 1 -name 'seed-*+*' | sort | head -1)
[ -n "$c" ] || die "no pair's directory in $o/pairs"
st=0; timeout 120 "$PATINA" run --seed $s --config "$c/run.json" --out "$o/rerun2" -- $D >/dev/null 2>&1 || st=$?
d1=$(field "$o/rerun2/result.json" digest) d2=$(field "$c/result.json" digest)
[ "$d1" = "$d2" ] || die "rerun of $c: digest $d1, not $d2"
echo "pair rerun ($(basename "$c")): same digest"
