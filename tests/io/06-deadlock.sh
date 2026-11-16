# 6. Deadlock detection still works: a thread blocked reading a pipe nobody writes, every
#    other thread exited -> deadlock, and the detail names the descriptor (and the call).
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-deadlock; mkdir -p "$o"
for rep in a b; do
    timeout 120 "$PATINA" run --seed 1 --out "$o/$rep" --guest "$PATINA_GUESTS" -- /guest/iodead >/dev/null 2>&1 || die "patina run exit"
    [ "$(field "$o/$rep/outcome.json" class)" = deadlock ] || die "class $(field "$o/$rep/outcome.json" class)"
done
[ "$(field "$o/a/outcome.json" digest)" = "$(field "$o/b/outcome.json" digest)" ] || die "two digests"
detail=$(field "$o/a/outcome.json" detail)
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
echo "same digest twice: $(field "$o/a/outcome.json" digest)"
