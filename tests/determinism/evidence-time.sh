# Evidence (time variant): every W1-W9 workload and attack guest, two runs
# DET_TIME_GAP_S apart (default 600 s, long enough for host-side background work such as
# XFS's 300 s preallocation trim), the gaps overlapped by tests/determinism/bin/timeall.sh.
#@ tier=evidence budget=1800 slots=2 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
PATINA_TIME_GAP_S=${DET_TIME_GAP_S:-600} bash "$determinism/bin/timeall.sh" "${DET_TIME_WLS:-$W_ALL $A_ALL}" | tee "$RUNS/timeall.txt"
bad=$(awk '!/ time identical$/' "$RUNS/timeall.txt")
[ -z "$bad" ] || die "time variant differs: $bad"
