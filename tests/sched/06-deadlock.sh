# 6. Deadlock guest: outcome liveness, stop deadlock; the detail names both threads' futex waits (on the two
#    mutexes the guest printed); same seed, same digest.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
for rep in a b; do
    out=$RUNS/06-deadlock/$rep
    patina_run "$out" 1 deadlock
    [ "$(field "$out/result.json" outcome)/$(field "$out/result.json" stop)" = liveness/deadlock ] || die "outcome $(field "$out/result.json" outcome) $(field "$out/result.json" stop)"
done
out=$RUNS/06-deadlock/a
lhs=$(field "$out/result.json" digest); rhs=$(field "$RUNS/06-deadlock/b/result.json" digest)
[ "$lhs" = "$rhs" ] || die "two digests"
detail=$(field "$out/result.json" message)
echo "detail: $detail"
python3 -I - "$detail" "$out/inc-0/stdout" <<'PY' || die "detail does not name both threads' waits on the two mutexes"
import re, sys
detail, stdout = sys.argv[1], open(sys.argv[2]).read().split()
m1, m2 = int(stdout[1], 16), int(stdout[3], 16)
waits = {}
for part in detail.split(";"):
    kv = dict(x.split("=", 1) for x in part.split() if "=" in x)
    if kv.get("wait") == "futex":
        waits[int(kv["tid"])] = int(kv["addr"], 16)
# The two worker threads wait on m1 and m2 (one each); main waits on a join.
mutex_waiters = sorted(t for t, a in waits.items() if a in (m1, m2))
assert len(mutex_waiters) == 2 and {waits[t] for t in mutex_waiters} == {m1, m2}, waits
print("threads", mutex_waiters, "wait on", hex(m1), hex(m2))
PY
echo "same digest twice: $(field "$out/result.json" digest)"
