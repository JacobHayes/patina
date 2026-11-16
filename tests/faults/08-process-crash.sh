# 8. Process crash: the variant without the record fsync passes under --crash process:20
# (the page cache survives a process crash), PCRASH_SEEDS seeds (default 40; faults: 100). The
# expected contrast with item 7.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
N=${PCRASH_SEEDS:-40}
sweep 08 "$N" --crash process:20 -- /guest/ack-log nofsync
python3 -I - "$RUNS/08/summary.tsv" <<'PY' || exit 1
import csv, sys
oc = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
bad = [o for o in oc if o["class"] != "ok"]
c1 = sum(1 for o in oc if int(o["crashes"]))
print("nofsync under process:20: %d runs, %d ok, %d with >= 1 process crash" % (len(oc), len(oc) - len(bad), c1))
if bad:
    sys.exit("FAIL: seed %s: %s %s" % (bad[0]["seed"], bad[0]["class"], bad[0]["detail"]))
if c1 == 0:
    sys.exit("FAIL: no process crash")
PY
