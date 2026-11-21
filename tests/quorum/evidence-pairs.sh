# Evidence (docs/EVIDENCE.md, "Two crashes: pairs of crash points"): `patina sweep
# --crash-points=400 --crash machine` with crash-pairs 3 on q3.py (three replicas, 2 s of virtual
# time), seeds 1..2, each variant once at -j 6 with --keep fail: the correct store, `nosync` (a
# node answers before it syncs) and `early` (the primary answers before a backup has the
# update). Each line: crash points, first crashes tried, pairs found after them and tried,
# runs, wall seconds, failing first crashes and pairs, and the failures' labels.
#@ tier=evidence budget=900 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/evidence-pairs; mkdir -p "$o"
for v in ok nosync early; do
    f=$o/$v.toml; rm -f "$f"
    b=""; [ $v = ok ] || b=$v
    for n in n1 n2 n3; do conf "$f" "$n" python3 /guest/q3.py "$n" $b; done
    printf '[sweep]\ncrash-pairs = 3\n' >>"$f"
    rm -rf "${o:?}/$v"
    t0=$(date +%s); st=0
    timeout 800 "$PATINA" sweep --seeds 1..2 --crash-points=400 --crash machine -j 6 --keep fail \
        --out "$o/$v" --config "$f" --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/q3.py driver 2 >"$o/$v.txt" 2>&1 || st=$?
    [ -f "$o/$v/report.json" ] || die "$v: no report (exit $st): $(tail -3 "$o/$v.txt")"
    python3 -I - "$o/$v/report.json" "$v" "$(( $(date +%s) - t0 ))" <<'PY'
import collections, json, os, re, sys
rep, name, wall = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
b = rep["crash_points"]
runs = [x for g in rep["groups"] for x in g["runs"]]
labels = collections.Counter()
# Labels from the runs whose output the sweep kept (each group's first three).
for x in runs:
    if not os.path.isfile(x["dir"] + "/inc-0/stdout"):
        continue
    out = open(x["dir"] + "/inc-0/stdout").read()
    m = re.search(r"^FAIL: ([a-z ]+):", out, re.M)
    labels[m[1] if m else "other"] += 1
print("%-7s seeds 1-2: points %d, %d first crashes tried, pairs %d of %d tried, %d runs, %s s wall, "
      "failing: %d first crashes, %d pairs; %s"
      % (name, b["points"], b["tried"], b["pairs"]["tried"], b["pairs"]["pairs"], rep["runs"], wall,
         sum("point2" not in x for x in runs), sum("point2" in x for x in runs),
         ", ".join("%s %d" % kv for kv in sorted(labels.items())) or "-"))
PY
done
