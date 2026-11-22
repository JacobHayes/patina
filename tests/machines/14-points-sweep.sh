# 14. Machines: crash points, fuller (tests/guests/machines/ack2.py, as 13-points). A `--crash-points` sweep
# over four seeds of `early` (two in the release tier) finds the lost acknowledged put on b in
# each seed and in b's children only, and the correct store is ok at every point of every machine.
# A run crashing at per-mille chance at both machines' points is identical under verify --vary,
# replays identically, and passes the operation-log self-check of every machine disk (`log ops
# --check`). `minimize`
# reduces a planted failure (crashes at both machines' points, net delays and duplicates, disk
# delays) to what it needs: a crash kept at points was tried as one machine's crash alone, one
# kept at a point is b's (`crash-at=N@b`), and every fault setting left was tried without
# and no longer failed. Which settings a failure needs depends on its seed, and the failing
# seed found depends on the host: on the reference host it is the crash alone.
# A failure built to need b's later crash, not its first (`lazy init`, any seed), is reduced to
# that later crash alone, at its place in a first boot, b's first crash alone having been tried
# first and not failed.
# A machine with `faults = false` is left out of `--faults crash` given without a scope.
#@ tier=area,release budget=120 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/14-points-sweep; mkdir -p "$o"
for v in ok early; do
    rm -f "$o/$v.toml"
    conf "$o/$v.toml" a python3 /guest/ack2.py a; printf 'ready = "patina wait :7000"\n' >> "$o/$v.toml"
    if [ $v = ok ]; then conf "$o/$v.toml" b python3 /guest/ack2.py b; else conf "$o/$v.toml" b python3 /guest/ack2.py b early; fi
    printf 'ready = "patina wait :7000"\n' >> "$o/$v.toml"
    main_unfaulted "$o/$v.toml"
done
D="python3 /guest/ack2.py main 4"
S=4; [ "${CHECK_TIER:-}" != release ] || S=2
sw() { rm -rf "${o:?}/sw-$1"; st=0; timeout 600 "$PATINA" sweep --seeds 1..$S --crash-points --faults crash -j 6 --keep "$2" --out "$o/sw-$1" \
    --config "$o/$1.toml" --mount "$PATINA_GUESTS":/guest:copy -- $D >"$o/sw-$1.txt" 2>&1 || st=$?; }
sw early fail
[ "$st" = 1 ] || die "branch sweep of early: exit $st: $(tail -5 "$o/sw-early.txt")"
python3 -I - "$o/sw-early" "$S" <<'PY' || die "branch sweep of early"
import json, os, sys
rep = json.load(open(os.path.join(sys.argv[1], "report.json")))
br = rep["crash_points"]
assert br["tried"] == br["points"], br
fails = [r for g in rep["groups"] for r in g["runs"]]
assert all("lost on b" in g["signature"] for g in rep["groups"]), [g["signature"] for g in rep["groups"]]
assert {r["machine"] for r in fails} == {"b"}, {r["machine"] for r in fails}
assert {r["seed"] for r in fails} == set(range(1, int(sys.argv[2]) + 1)), {r["seed"] for r in fails}
print("early: %d of %d points fail, in every seed, on b only" % (len(fails), br["points"]))
PY
sw ok fail
[ "$st" = 0 ] || die "branch sweep of ok: exit $st: $(tail -5 "$o/sw-ok.txt")"
grep '^crash points:' "$o/sw-ok.txt"
# Per-mille crashes at both machines' points: determinism and the self-check of each machine disk.
# A run has about 19 points per machine, so about one seed in ten crashes neither machine: the first
# seed from a random start that crashes one.
P="--config $o/ok.toml --fault crash-permille=60"
s0=$((RANDOM % 100 + 1)); s=""
for t in $(seq "$s0" $((s0 + 9))); do
    run_ok "$o/p" "$t" $P -- $D
    python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(sum(len(n.get("downs", [])) for n in r["machines"]["list"]) == 0)' \
        "$o/p/result.json" && { s=$t; break; }
done
[ -n "$s" ] || die "seeds $s0..$((s0 + 9)): no machine crashed at a point"
verify_ok "$o/verify" "$s" 3 $P -- $D
"$PATINA" log ops --check "$o/p" >"$o/check.txt" || die "log ops --check: $(cat "$o/check.txt")"
for n in a b; do grep -q "/machine/$n/boot-1: ok " "$o/check.txt" || die "log ops --check: no disk of $n: $(cat "$o/check.txt")"; done
st=0; timeout 300 "$PATINA" replay "$o/p" >"$o/replay.txt" 2>&1 || st=$?
grep -q '^identical' "$o/replay.txt" || die "replay: exit $st: $(head -3 "$o/replay.txt")"
echo "seed $s: replay identical, every machine disk passes log ops --check"
# Minimize a planted multi-fault failure: search seeds for one that fails (about one in four).
F="--config $o/early.toml --fault crash-permille=60 --fault net-delay-ms=0..20 --fault net-dup-permille=10 --fault fs-delay-permille=20"
found=""
for s in $(seq 1 $FIND_SEEDS); do
    [ "$(run "$o/m" $s $F -- $D)" = failure ] && { found=$s; break; }
done
[ -n "$found" ] || die "no seed of 1-$FIND_SEEDS fails with $F"
st=0; timeout 900 "$PATINA" minimize "$o/m" --format json >"$o/min.json" 2>"$o/min.err" || st=$?
python3 -I - "$o/m" "$o/min.json" <<'PY' || die "minimize: exit $st: $(tail -3 "$o/min.err")"
import json, os, re, sys
d = sys.argv[1]
m = json.load(open(sys.argv[2]))
assert m["reduced"] and m["runs"] < m["max_runs"], m
run = json.load(open(os.path.join(d, "minimized", "run.json")))
c = run["config"]
crash = [f for f in c.get("faults") or [] if f.startswith("crash-")]
faults = [f for f in c.get("faults") or [] if not f.startswith("crash-")]
assert len(crash) == 1, c
if crash[0].startswith("crash-at="):
    assert re.fullmatch(r"crash-at=\d+@b", crash[0]), crash
else:
    # Each machine's crash alone was tried, and none failed the same way.
    t = [x for x in m["tries"] if "-> crash-at=" in x["change"]]
    assert crash[0].startswith("crash-permille=") and t and not any(x["still_fails"] for x in t), (crash, m["tries"])
for f in faults:
    # The last try without the setting no longer failed.
    t = [x for x in m["tries"] if x["change"].startswith("without %s=" % f.split("=")[0])]
    assert t and not t[-1]["still_fails"], (f, m["tries"])
print("minimize: reduced to %s (from %s)" % (m["to"], m["from"]))
PY
# A failure that a machine's first crash alone does not give is reduced to its later crash alone, at
# its place in a first boot. Built, not searched for: b (`lazy init`) syncs its directory before
# it serves its first request, on its first boot only, and appends a put only at its next
# request, which a sends once it has the answer; main (`wait`) starts once a and b serve (their
# `ready` probes), then waits for b to answer. A crash at each of b's points (`crash-permille=1000@b`) in at most 3
# boots crashes b twice, whatever the seed and host: first at that directory sync (harmless),
# then at the create of `log` for put 1, which a has acknowledged.
o2=$o/later; mkdir -p "$o2"; rm -f "$o2/c.toml"
conf "$o2/c.toml" a python3 /guest/ack2.py a; printf 'ready = "patina wait :7000"\n' >> "$o2/c.toml"
conf "$o2/c.toml" b python3 /guest/ack2.py b lazy init
printf 'max-boots = 3\nready = "patina wait :7000"\n' >>"$o2/c.toml"
s=$((RANDOM % 1000 + 1))
[ "$(run "$o2/l" $s --config "$o2/c.toml" --fault crash-permille=1000@b -- python3 /guest/ack2.py main 2 wait)" = failure ] \
    || die "seed $s: the built run did not fail: $(field "$o2/l/result.json" message)"
st=0; timeout 300 "$PATINA" minimize "$o2/l" --format json >"$o2/l.json" 2>"$o2/l.err" || st=$?
[ "$st" = 0 ] || die "minimize seed $s: exit $st: $(tail -3 "$o2/l.err")"
"$PATINA" log events "$o2/l" --types op,crash >"$o2/l.ev" || die "log events $o2/l"
"$PATINA" log events "$o2/l/minimized" --types op,crash >"$o2/m.ev" || die "log events $o2/l/minimized"
python3 -I - "$o2/l" "$o2/l.json" "$o2/l.ev" "$o2/m.ev" <<'PY' || die "seed $s: minimize of a failure needing b's later crash"
import json, os, re, sys
d, m = sys.argv[1], json.load(open(sys.argv[2]))
def b_events(f):
    ev = [json.loads(l) for l in open(f)]
    ev = [e for e in ev if e.get("machine") == "b"]
    creates = {e["seq"] for e in ev if e["type"] == "op" and e["op"] == "create" and e["path"] == "/work/log"}
    return ev, [e for e in ev if e["type"] == "crash"], creates
r = json.load(open(os.path.join(d, "result.json")))
assert "lost on b" in r["signature"], r["signature"]
downs = r["machines"]["list"][2]["downs"]
assert len(downs) == 2, downs
ev, crashes, creates = b_events(sys.argv[3])
assert len(crashes) == 2, crashes
# The first crash: before b's first operation, the directory sync. The later one: at the create
# of log for put 1.
assert ev[0] is crashes[0], ev[:3]
assert crashes[1]["seq"] in creates, (crashes[1], creates)
first = downs[0]["point"]
singles = [t for t in m["tries"] if "-> crash-at=" in t["change"]]
assert singles and singles[0]["change"].endswith(" -> crash-at=%d@b" % first) and not singles[0]["still_fails"], m["tries"]
assert m["reduced"] and m["runs"] < m["max_runs"], m
crash = [f for f in json.load(open(os.path.join(d, "minimized", "run.json")))["config"].get("faults") or [] if f.startswith("crash-")]
x = len(crash) == 1 and re.fullmatch(r"crash-at=(\d+)@b", crash[0])
assert x and int(x[1]) != first, (crash, first, m["tries"])
n = int(x[1])
# The crash kept: the later crash's place in a first boot, at the create of log.
_, mc, mcreates = b_events(sys.argv[4])
assert [c["point"] for c in mc] == [n] and mc[0]["seq"] in mcreates, (mc, mcreates)
print("minimize: b's later crash alone: %s (b's first crash alone, at point %d, did not fail), from %s" % (m["to"], first, m["from"]))
PY
# faults = false: an unscoped crash leaves the machine out.
rm -f "$o/free.toml"
conf "$o/free.toml" a python3 /guest/ack2.py a; printf 'ready = "patina wait :7000"\n' >> "$o/free.toml"
conf "$o/free.toml" b python3 /guest/ack2.py b; printf 'faults = false\nready = "patina wait :7000"\n' >>"$o/free.toml"; main_unfaulted "$o/free.toml"
run_ok "$o/free" 1 --config "$o/free.toml" --fault crash-permille=300 -- $D
python3 -I - "$o/free/result.json" <<'PY' || die "faults = false"
import json, sys
r = json.load(open(sys.argv[1]))
a, b = r["machines"]["list"][1], r["machines"]["list"][2]
assert a.get("downs") and not b.get("downs") and "crash_points" not in b, (a, b)
print("faults = false: a crashed %d times, b none" % len(a["downs"]))
PY
