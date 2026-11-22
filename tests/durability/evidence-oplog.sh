# Evidence (the crash materialiser): the tracker self-check (`patina log ops --check`, replay of the whole log = the
# live tree, every boot) on W1-W9, seeds 1-3, faults off and on (tests/durability/bench/oplog.py).
#@ tier=evidence budget=600 slots=1 arch=x86_64
: "${PATINA:?}" "${RUNS:?}"
mkdir -p "$RUNS/oplog"
python3 -I "$(dirname "$0")/bench/oplog.py" "$RUNS/oplog" | tee "$RUNS/oplog.txt"
n=$(awk '/check-exit 0/ {n++} END {print n + 0}' "$RUNS/oplog.txt"); t=$(wc -l <"$RUNS/oplog.txt")
echo "oplog check: $n of $t runs replay to the live tree"
[ "$n" = "$t" ] && [ "$t" -ge 54 ]
