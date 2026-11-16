# Evidence (cost measurement outcome census and throughput, docs/EVIDENCE.md cost measurement): SEEDS seeds (default 100; the
# recorded census used 200) of each workload with its fault configuration, 8 runs at a time (tests/durability/bench/census.py).
#@ tier=evidence budget=1200 slots=8
set -eu
: "${PATINA:?}" "${RUNS:?}"
OUT=$RUNS/census JOBS=8 SEEDS=${SEEDS:-100} python3 -I "$(dirname "$0")/bench/census.py" W1 W2 W3 W4 W5 W6 W7 W8 W9
