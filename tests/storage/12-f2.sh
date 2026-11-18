# 12. F2 (fjall's journal-entry assertion: after a machine crash the journal keeps the block
# holding an item's value_len and loses the next one, holding its on_disk_value_len) is found
# by trying every crash point: `sweep --branch` over seeds 1-3, stopped at the first finding,
# which must be the panic in fjall's journal/entry.rs. FJ_VAL_SHIFT=289 lays the journal out so
# that batch 5 straddles the first 4 KiB block boundary that way (at the default layout the
# first such batch is about 800, some 1,700 to 3,000 crash points in, minutes of runs:
# docs/EVIDENCE.md, "Crash-point enumeration"); here the window lies about 240 points in.
# FJ_WIPE_PARTIAL=1: the early open-after-crash finding (F1) recovers instead of ending the
# sweep. F2_N sets FJ_N (5: the journal ends before batch 5, no straddling item: red).
#@ tier=release budget=120 slots=4
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/f2
"$PATINA" sweep -j 4 --seeds 1..3 --branch --crash machine --buggify \
    --env "FJ_N=${F2_N:-100}" --env FJ_VAL_SHIFT=289 --env FJ_WIPE_PARTIAL=1 --max-findings 1 \
    --keep fail --out "$o" \
    --mount "$W/fjall-harness":/guest:copy -- /guest/fjall-harness-debug >"$o.txt" 2>&1 || true
[ -f "$o/report.json" ] || die "no report: $(tail -3 "$o.txt")"
python3 -I - "$o/report.json" <<'PY' || { tail -12 "$o.txt"; exit 1; }
import json, sys
r = json.load(open(sys.argv[1]))
g = [g for g in r["groups"] if g["outcome"] == "failure" and "journal/entry.rs" in g["signature"]]
b = r["branch"]
print("crash points %d of %d tried; groups: %s" % (b["tried"], b["points"], ["%s (%d, first %s@%s)" % (x["signature"][:60], x["count"], x["first"]["seed"], x["first"]["point"]) for x in r["groups"]]))
if not g:
    sys.exit("FAIL: no group with fjall's journal-entry assertion")
PY
