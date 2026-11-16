# 9. A guest looping without a syscall ends as stall within --stall-ms 500 plus 2.5 s, and leaves no process behind.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
out=$RUNS/09-stall
t0=$(date +%s%N)
timeout 30 "$PATINA" run --seed 1 --stall-ms 500 --out "$out" --guest "$PATINA_GUESTS" -- /guest/spin
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
[ "$(field "$out/outcome.json" class)" = stall ] || die "class $(field "$out/outcome.json" class)"
[ "$ms" -le 3000 ] || die "took $ms ms"
# No process of this run is left (launcher, bwrap, supervisor or guest; see tests/leftovers.py).
left=$(python3 -I "$(dirname "$0")/../leftovers.py" "$out" || true)
[ -z "$left" ] || die "processes left: $left"
echo "stall after $ms ms, no process left"
