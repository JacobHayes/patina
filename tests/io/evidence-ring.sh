# Evidence (blocking I/O item 5, the lost-wake-up claim): 05-ring at volume, 24 seeds x 25,000 laps,
# 8 runs at a time. blocking I/O's own run was 50 seeds x 100,000 laps (24 min); this is about a
# tenth of that volume, so the evidence tier stays within its hour.
#@ tier=evidence budget=900 slots=8
RING_SEEDS=${RING_SEEDS:-24} RING_LAPS=${RING_LAPS:-25000} RING_JOBS=8 exec sh "$(dirname "$0")/05-ring.sh"
