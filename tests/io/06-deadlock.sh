# 6. Deadlock detection still works: a thread blocked reading a pipe nobody writes, every
#    other thread exited -> liveness (deadlock), and the detail names the descriptor (and the call).
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-deadlock; mkdir -p "$o"
for rep in a b; do
    # lint-allow: seed — no other thread is left to write the pipe, so every seed deadlocks
    timeout 120 "$PATINA" run --seed 1 --out "$o/$rep" --mount "$PATINA_GUESTS":/guest:copy -- /guest/iodead >/dev/null 2>&1 || [ -f "$o/$rep/result.json" ] || die "patina run: no result.json"
    [ "$(field "$o/$rep/result.json" outcome)/$(field "$o/$rep/result.json" stop)" = liveness/deadlock ] || die "outcome $(field "$o/$rep/result.json" outcome) $(field "$o/$rep/result.json" stop)"
done
[ "$(field "$o/a/result.json" digest)" = "$(field "$o/b/result.json" digest)" ] || die "two digests"
detail=$(field "$o/a/result.json" message)
echo "detail: $detail"
fd=$(sed -n 's/^read fd \([0-9]*\)$/\1/p' "$o/a/inc-0/stdout")
python3 -I - "$detail" "$fd" <<'PY'
import sys
detail, fd = sys.argv[1], sys.argv[2]
parked = [dict(x.split("=", 1) for x in p.split() if "=" in x) for p in detail.split(";")]
assert len(parked) == 1, parked  # main exited: only the reader is left
p = parked[0]
assert p["wait"] == "io" and p["fd"] == fd and p["dir"] == "in" and p["call"] == "read", p
print("the one parked thread waits on fd", fd, "(read)")
PY
echo "same digest twice: $(field "$o/a/result.json" digest)"
