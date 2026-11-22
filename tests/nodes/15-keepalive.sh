# 15. Nodes: TCP keepalive across node failures (tests/guests/nodes/ka.py; ARCHITECTURE.md, "The
# fault plan"). With idle 2 s, interval 1 s and 3 probes (Linux's tcp_keepalive_timer:
# give up after idle + 3 x interval with nothing heard): a peer whose machine crashed and stays
# down times out at that budget (with TCP_USER_TIMEOUT 3500 ms, at the first probe past it); one
# that comes back within it answers a probe with a RST (ECONNRESET); a cut shorter than the
# budget changes nothing, a longer one times out both sides; a pause of b (`pause b`)
# shorter or longer than the budget acts as a cut of that length. A run replays identically.
# Expected on the arm64 runner: about 3 s.
#@ tier=quick budget=60 slots=1
. "$(dirname "$0")/lib.inc"
o=$RUNS/15-keepalive; mkdir -p "$o"
rm -f "$o/b.toml"; conf "$o/b.toml" b python3 /guest/ka.py b
for m in crash ut restart short long pause-short pause-long; do
    run_ok "$o/$m" 1 --config "$o/b.toml" -- python3 /guest/ka.py driver $m
    sed 's/^/    /' "$o/$m/inc-0/stdout"
done
grep -q '^b: ETIMEDOUT after 5\.0' "$o/long/node/b/inc-0/stdout" || die "b's side of the long cut: $(cat "$o/long/node/b/inc-0/stdout")"
echo "    $(cat "$o/long/node/b/inc-0/stdout")"
st=0; timeout 300 "$PATINA" replay "$o/restart" >"$o/replay.txt" 2>&1 || st=$?
grep -q '^identical' "$o/replay.txt" || die "replay: exit $st: $(head -3 "$o/replay.txt")"
echo "replay: identical"
