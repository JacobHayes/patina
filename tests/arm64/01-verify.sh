# 1. hello-static under `verify --vary repeat,cpu,aslr`: the runs are identical.
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
"$PATINA" verify --runs 3 --vary repeat,cpu,aslr --seed 1 --out "$RUNS/verify" \
    -- "$PATINA_GUESTS/hello-static" >"$RUNS/verify.txt" 2>&1 || die "verify: $(tail -3 "$RUNS/verify.txt")"
cat "$RUNS/verify.txt"
