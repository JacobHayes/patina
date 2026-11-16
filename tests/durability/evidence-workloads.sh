# Evidence (workload matrix): W1-W9, evidence R and D and the
# tracker self-check (tests/durability/lib/matrix.py; COSTS_D_SEEDS and COSTS_D_RUNS, defaults 5 and 20),
# 8 workloads at a time. F is each workload's own area script (named in the table).
#@ tier=evidence budget=1800 slots=8
set -eu
: "${PATINA:?}" "${RUNS:?}" "${PATINA_WORKLOADS:?}" "${PATINA_GUESTS:?}"
here=$(cd "$(dirname "$0")" && pwd)
printf '%s\n' W1 W2 W3 W4 W5 W6 W7 W8 W9 | xargs -P 8 -I{} sh -c 'python3 -I "$1/lib/matrix.py" "$2/{}" {} >"$2/{}.out" 2>&1; echo "{} exit $?"' sh "$here" "$RUNS"
fail=0
for w in W1 W2 W3 W4 W5 W6 W7 W8 W9; do
    tail -n +2 "$RUNS/$w/matrix.tsv" 2>/dev/null || { echo "$w: no result ($(tail -2 "$RUNS/$w.out"))"; fail=1; }
    grep -q 'FAIL' "$RUNS/$w/matrix.tsv" 2>/dev/null && fail=1
done
exit $fail
