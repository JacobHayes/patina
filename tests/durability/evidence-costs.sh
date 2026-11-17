# Evidence (cost tables, docs/EVIDENCE.md): start-up phases and end-to-end wall time per
# workload, native vs patina; REPS runs each (default 5), each pinned
# to one core. percall.py (needs a --cfg patina_nolog runtime), patina.py (needs Patina v0.5.0)
# and spin.py are run by hand (their docstrings). materialise.py reads launcher timing marks
# from before the crash materialiser and no longer runs; crash work against log size is tests/durability/bench.py size
# (./check evidence durability/evidence-speed).
#@ tier=evidence budget=1200 slots=1 arch=x86_64
set -eu
: "${PATINA:?}" "${RUNS:?}"
b=$(dirname "$0")/bench
export OUT=$RUNS/costs REPS=${REPS:-5}
for s in startup e2e; do
    echo "== $s"
    python3 -I "$b/$s.py"
done
