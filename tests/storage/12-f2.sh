# 12. F2 (fjall's journal-entry assertion, a crash in a window of a few crash points between a
# journal write and the next journal fsync) is found by trying every crash point:
# `sweep --branch` over seeds 1-2 with FJ_WIPE_PARTIAL=1 (so the early open-after-crash
# finding recovers instead of filling the finding count), stopped at the second finding group
# (the other is F6, which seed 2 reaches first). One of the two must be the panic in fjall's
# journal/entry.rs. The window lies about 1,700
# points into a seed (docs/EVIDENCE.md, "Crash-point enumeration"), several minutes of runs,
# so this is a nightly check. F2_N sets FJ_N (a short journal holds no straddling batch: red).
# x86_64 only: on the 4-core arm64 runner the two seeds take longer than the budget.
#@ tier=nightly budget=400 slots=6 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/f2
timeout 1200 "$PATINA" sweep -j 6 --seeds 1..2 --branch --crash machine --buggify \
    --env "FJ_N=${F2_N:-2000}" --env FJ_WIPE_PARTIAL=1 --max-findings 2 --keep fail --out "$o" \
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
