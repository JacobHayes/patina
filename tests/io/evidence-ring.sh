# Evidence (the lost-wake-up claim): 05-ring at volume, 24 seeds x 25,000 laps,
# 8 runs at a time; the volume is kept low so the evidence tier stays within its hour (RING_SEEDS
# and RING_LAPS raise it).
#@ tier=evidence budget=900 slots=8 arch=x86_64
RING_SEEDS=${RING_SEEDS:-24} RING_LAPS=${RING_LAPS:-25000} RING_JOBS=8 exec sh "$(dirname "$0")/05-ring.sh"
