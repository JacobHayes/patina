# 8. Process crash: the variant without the record fsync passes under --faults kill with crash-permille=20
# (the page cache survives a process crash), PCRASH_SEEDS seeds (default 20; evidence: 100). The
# expected contrast with the machine-crash case in 07-acklog.sh.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
N=${PCRASH_SEEDS:-20}
sweep 08 "$N" --faults kill --fault crash-permille=20 -- /guest/ack-log nofsync
python3 -I - "$RUNS/08/summary.tsv" <<'PY' || exit 1
import csv, sys
oc = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
bad = [o for o in oc if o["outcome"] != "ok"]
c1 = sum(1 for o in oc if int(o["crashes"]))
print("nofsync under kill, crash-permille=20: %d runs, %d ok, %d with >= 1 process crash" % (len(oc), len(oc) - len(bad), c1))
if bad:
    sys.exit("FAIL: seed %s: %s %s" % (bad[0]["seed"], bad[0]["outcome"], bad[0]["message"]))
if c1 == 0:
    sys.exit("FAIL: no process crash")
PY
