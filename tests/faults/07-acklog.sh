# 7. Crash and restart end to end with ack-log: under --crash machine:20, ACK_SEEDS seeds
# (default 40) per model, both models, every run ok, some with >= 1 crash and some with >= 2
# (the recorded run: 200 seeds, at least 50 and 10; tests/faults/evidence-crashes.sh). The
# variant without the record fsync fails with INVARIANT acked-record-lost under each model
# (the first such seed of 1-100); that seed run twice gives the same digest and the same
# post-crash trees. Also: turning crashes on does not change the run before the crash
# (boundary logs equal up to the crash seq).
#@ tier=area budget=120 slots=4
. "$(dirname "$0")/lib/common.inc"
N=${ACK_SEEDS:-40}
for m in ext4-ordered posix-strict; do
    d=$RUNS/07/$m
    mkdir -p "$d"
    sweep 07/$m-correct "$N" --fs-model $m --crash machine:20 -- /guest/ack-log correct
    python3 -I - "$RUNS/07/$m-correct/summary.tsv" "$m" "$N" <<'PY' || exit 1
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
m, n = sys.argv[2], int(sys.argv[3])
bad = [r for r in rows if r["class"] != "ok"]
c1 = sum(1 for r in rows if int(r["crashes"]) >= 1)
c2 = sum(1 for r in rows if int(r["crashes"]) >= 2)
print("%s: %d runs, %d ok, >=1 crash: %d, >=2 crashes: %d, crashes in all: %d" % (
    m, len(rows), len(rows) - len(bad), c1, c2, sum(int(r["crashes"]) for r in rows)))
if bad:
    sys.exit("FAIL: %s seed %s: %s %s" % (m, bad[0]["seed"], bad[0]["class"], bad[0]["detail"]))
if len(rows) != n or c1 == 0 or c2 == 0:
    sys.exit("FAIL: no run crashed (twice)")
PY
    # The planted bug: no fsync of the record before the acknowledgement.
    sweep 07/$m-nofsync 100 --fs-model $m --crash machine:20 -- /guest/ack-log nofsync
    found=$(awk -F'\t' '$2 == "failed" && $3 ~ /INVARIANT acked-record-lost/ {print $1; exit}' "$RUNS/07/$m-nofsync/summary.tsv")
    [ -n "$found" ] || die "$m: nofsync never caught in 100 seeds"
    run "$d/nofsync-$found" "$found" --fs-model $m --crash machine:20 -- /guest/ack-log nofsync
    echo "$m: nofsync caught at seed $found: $(field "$d/nofsync-$found/outcome.json" detail)"
    run "$d/nofsync-$found-again" "$found" --fs-model $m --crash machine:20 -- /guest/ack-log nofsync
    a=$(field "$d/nofsync-$found/outcome.json" digest)
    b=$(field "$d/nofsync-$found-again/outcome.json" digest)
    [ "$a" = "$b" ] || die "$m seed $found: digests $a vs $b"
    n=0
    for p in "$d/nofsync-$found"/inc-*/post-crash; do
        q=$d/nofsync-$found-again/${p#"$d/nofsync-$found/"}
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
c = json.load(open(b + "/outcome.json"))["crashes"][0]["seq"]
recs = lambda p: [x[i:i + 96] for x in [open(p, "rb").read()] for i in range(0, len(x), 96)]
ra, rb = recs(a + "/inc-0/boundary.log"), recs(b + "/inc-0/boundary.log")
pre = [r for r in rb if struct.unpack_from("<Q", r, 0)[0] < c]
if ra[:len(pre)] != pre:
    sys.exit("FAIL: boundary logs differ before the crash at seq %d" % c)
print("crash at seq %d: the %d boundary records before it equal the run without --crash" % (c, len(pre)))
PY
