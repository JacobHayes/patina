# 4. Timeouts in virtual time: poll and epoll_wait with 10 s on a silent pipe return 0 after
#    >= 10 virtual seconds and in less wall time than that (no real wait); a 1 s periodic timerfd read 100 times reports
#    100 expirations at exact virtual times; SO_RCVTIMEO 2 s gives EAGAIN at 2 virtual s.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-timeouts; mkdir -p "$o"
for m in poll epoll timerfd rcvtimeo; do
    run_ok "$o/$m" 1 -- /guest/timeouts "$m"
    echo "$m: wall_ms $(field "$o/$m/result.json" wall_ms); $(head -1 "$o/$m/inc-0/stdout")"
done
python3 -I - "$o" <<'PY'
import json, re, sys
o = sys.argv[1]
def out(m): return open(f"{o}/{m}/inc-0/stdout").read().split("\n")
def wall(m): return json.load(open(f"{o}/{m}/result.json"))["wall_ms"]
S = 10**9
for m in ("poll", "epoll"):
    r, ns = re.match(r"\S+ ret (-?\d+) elapsed_ns (\d+)", out(m)[0]).groups()
    assert int(r) == 0 and S * 10 <= int(ns) < S * 10 + 10**6, (m, r, ns)
    assert wall(m) < 10_000, (m, wall(m))  # a real wait alone takes 10 s
    print(f"{m}: 0 after {int(ns)} virtual ns, {wall(m)} ms wall")
lines = [l for l in out("timerfd") if l.startswith("read ")]
assert len(lines) == 100
for k, l in enumerate(lines, 1):
    i, n, at = map(int, re.match(r"read (\d+) expirations (\d+) at_ns (\d+)", l).groups())
    # The read returns at the expiry plus the charge of the traps after it (a few us).
    assert i == k and n == 1 and k * S <= at < k * S + 10**5, l
assert "timerfd total 100" in out("timerfd")
print(f"timerfd: 100 reads, 1 expiration each, at k s + {at - 100 * S} ns")
r = re.match(r"recv ret (-?\d+) errno (\w+) elapsed_ns (\d+)", out("rcvtimeo")[0]).groups()
assert r[0] == "-1" and r[1] == "EAGAIN" and 2 * S <= int(r[2]) < 2 * S + 10**6, r
print(f"rcvtimeo: EAGAIN after {r[2]} virtual ns")
PY
