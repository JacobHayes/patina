# Evidence (the crash materialiser): the tracker self-check (`patina log ops --check`, replay of the whole log = the
# live tree, every incarnation) on W1-W9, seeds 1-3, faults off and on (tests/durability/bench/oplog.py).
#@ tier=evidence budget=600 slots=1
set -eu
: "${PATINA:?}" "${RUNS:?}"
mkdir -p "$RUNS/oplog"
python3 -I "$(dirname "$0")/bench/oplog.py" "$RUNS/oplog" | tee "$RUNS/oplog.txt"
n=$(grep -c 'check-exit 0' "$RUNS/oplog.txt" || true); t=$(wc -l <"$RUNS/oplog.txt")
echo "oplog check: $n of $t runs replay to the live tree"
[ "$n" = "$t" ] && [ "$t" -ge 54 ]
