# 16. Attribution counts and the operation log's self-check. A configured class with nothing
# to act on shows eligible 0 (the net preset on a guest without sockets), while the disk
# classes on the same guest count eligible calls and every injected fault. With crashes on,
# a run whose operation log was corrupted (test hook PATINA_TEST_OPLOG_CORRUPT) ends internal.
#@ tier=quick budget=15
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/16
run "$d/counts" 1 --faults disk,net --fault fs-error-permille=50 -- /guest/io-errors tally
python3 -I - "$d/counts/result.json" <<'PY' || exit 1
import json, sys
f = json.load(open(sys.argv[1]))["faults"]
c = f["counts"]
print(json.dumps(c, sort_keys=True))
net = {k: v for k, v in c.items() if k.startswith("net-")}
if not net or any(v["eligible"] != 0 or v["injected"] != 0 for v in net.values()):
    sys.exit("FAIL: net classes on a guest without sockets: %s" % net)
fs = c.get("fs-error")
if not fs or fs["eligible"] == 0 or fs["injected"] == 0 or fs["injected"] > fs["eligible"]:
    sys.exit("FAIL: fs-error counts %s" % fs)
# every class but the per-delivery spreads (net-delay, net-halfclose) counts injected records
total = sum(v["injected"] for k, v in c.items() if k not in ("net-delay", "net-halfclose"))
if total != f["injected"]:
    sys.exit("FAIL: counts sum to %d, injected %d" % (total, f["injected"]))
if any(not e.get("object") for e in f["recent"]):
    sys.exit("FAIL: an event without its object: %s" % f["recent"])
print("last event:", json.dumps(f["recent"][-1], sort_keys=True))
PY
o=$d/corrupt
rm -rf "$o"
PATINA_TEST_OPLOG_CORRUPT=1 "$PATINA" run --seed 1 --out "$o" --mount "$PATINA_GUESTS":/guest:copy --crash machine:0 -- /guest/ack-log correct >/dev/null 2>&1 || true
[ "$(class "$o")" = internal ] || die "corrupted operation log: $(class "$o") $(field "$o/result.json" message)"
echo "corrupted operation log: internal ($(field "$o/result.json" message | cut -c1-120))"
run "$d/clean" 1 --crash machine:0 -- /guest/ack-log correct
[ "$(class "$d/clean")" = ok ] || die "self-check on a clean run: $(class "$d/clean") $(field "$d/clean/result.json" message)"
