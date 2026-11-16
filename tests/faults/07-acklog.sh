# 7. Crash and restart end to end with ack-log under --faults disk --crash machine: ACK_SEEDS
# seeds (default 20) per model, both models: the correct variant is ok on every seed and
# some runs crash (the recorded run: tests/faults/evidence-crashes.sh). The variant without
# the record fsync fails with INVARIANT acked-record-lost on at least one of ACK_SEEDS seeds
# under each model, and its result says why: faults.recent ends with the machine crash and
# names the file it changed. That seed run twice gives the same digest and the same post-crash
# trees. Also: turning crashes on does not change the run before the crash (boundary logs
# equal up to the crash seq).
#@ tier=quick budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
N=${ACK_SEEDS:-20}
for m in ext4-ordered posix-strict; do
    d=$RUNS/07/$m
    mkdir -p "$d"
    cfg=$("$PATINA_CFG" fs-model=$m faults-in-recovery=false)
    sweep 07/$m-correct "$N" --config "$cfg" --faults disk --crash machine -- /guest/ack-log correct
    python3 -I - "$RUNS/07/$m-correct/summary.tsv" "$m" "$N" <<'PY' || exit 1
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
m, n = sys.argv[2], int(sys.argv[3])
bad = [r for r in rows if r["outcome"] != "ok"]
c1 = sum(1 for r in rows if int(r["crashes"]) >= 1)
print("%s correct: %d runs, %d ok, >=1 crash: %d, crashes in all: %d" % (
    m, len(rows), len(rows) - len(bad), c1, sum(int(r["crashes"]) for r in rows)))
if bad:
    sys.exit("FAIL: %s seed %s: %s %s" % (m, bad[0]["seed"], bad[0]["outcome"], bad[0]["message"]))
if len(rows) != n or c1 == 0:
    sys.exit("FAIL: no run crashed")
PY
    # The planted bug: no fsync of the record before the acknowledgement.
    sweep 07/$m-nofsync "$N" --config "$cfg" --faults disk --crash machine -- /guest/ack-log nofsync
    found=$(awk -F'\t' '$2 == "failure" && $3 ~ /INVARIANT acked-record-lost/ {print $1; exit}' "$RUNS/07/$m-nofsync/summary.tsv")
    [ -n "$found" ] || die "$m: nofsync never caught in $N seeds"
    o=$d/nofsync-$found
    run "$o" "$found" --config "$cfg" --faults disk --crash machine -- /guest/ack-log nofsync
    python3 -I - "$o/result.json" "$m" "$found" <<'PY' || exit 1
import json, sys
r = json.load(open(sys.argv[1]))
last = r["faults"]["recent"][-1]
print("%s nofsync caught at seed %s: %s; plan %s; last fault: %s" % (
    sys.argv[2], sys.argv[3], r["message"], json.dumps(r["faults"]["plan"], sort_keys=True), json.dumps(last, sort_keys=True)))
if last["fault"] != "crash" or last["kind"] != "machine" or last.get("object") != "/work/data.log":
    sys.exit("FAIL: faults.recent does not end with the machine crash naming /work/data.log")
PY
    run "$o-again" "$found" --config "$cfg" --faults disk --crash machine -- /guest/ack-log nofsync
    a=$(field "$o/result.json" digest)
    b=$(field "$o-again/result.json" digest)
    [ "$a" = "$b" ] || die "$m seed $found: digests $a vs $b"
    n=0
    for p in "$o"/inc-*/post-crash; do
        q=$o-again/${p#"$o/"}
        diff -r "$p" "$q" >/dev/null || die "$m seed $found: post-crash trees differ ($p)"
        n=$((n + 1))
    done
    echo "$m: seed $found twice: digest $a both times, $n post-crash trees identical"
done
# Crashes on must not change the run before the crash.
run "$RUNS/07/plain" 3 -- /guest/ack-log correct
run "$RUNS/07/crash" 3 --crash machine:20 -- /guest/ack-log correct
python3 -I - "$RUNS/07/plain" "$RUNS/07/crash" <<'PY' || exit 1
import json, struct, sys
a, b = sys.argv[1], sys.argv[2]
c = json.load(open(b + "/result.json"))["crashes"][0]["seq"]
recs = lambda p: [x[i:i + 96] for x in [open(p, "rb").read()] for i in range(0, len(x), 96)]
ra, rb = recs(a + "/inc-0/boundary.log"), recs(b + "/inc-0/boundary.log")
pre = [r for r in rb if struct.unpack_from("<Q", r, 0)[0] < c]
if ra[:len(pre)] != pre:
    sys.exit("FAIL: boundary logs differ before the crash at seq %d" % c)
print("crash at seq %d: the %d boundary records before it equal the run without --crash" % (c, len(pre)))
PY
