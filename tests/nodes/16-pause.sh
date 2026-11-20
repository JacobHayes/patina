# 16. Nodes: pauses (tests/guests/nodes/pause.py). The driver pauses node b with `node pause b`
# and resumes it: a connection to b survives; b answers nothing while paused and at once after,
# its monotonic clock showing the time paused and its ticker's timers having fired late, not
# early; a sender's TCP_USER_TIMEOUT fires while b is paused (ETIMEDOUT); a second pause and a
# resume of a running node are EALREADY; a paused node can be killed, and a pause of a node
# that is down is EAGAIN. The seed's pauses (pause-gap-ms@b): result.json lists them, the
# events show each pause and resume, and the run is identical under verify --vary
# cpu,load,aslr,sandbox,repeat and under replay. A script's pause with no resume, with the
# driver waiting on b, ends the run `liveness`, naming b. Without nodes, and for the driver,
# the pause keys are refused.
#@ tier=quick budget=40 slots=2
# arm64 (CI runner): about 6 s.
. "$(dirname "$0")/lib.inc"
o=$RUNS/16-pause; mkdir -p "$o"
rm -f "$o/b.toml"; conf "$o/b.toml" b python3 /guest/pause.py b

run_ok "$o/script" 1 --config "$o/b.toml" -- python3 /guest/pause.py driver script
sed 's/^/    /' "$o/script/inc-0/stdout"
[ "$(field "$o/script/result.json" nodes.list.1.pauses)" = 3 ] || die "b's pauses: $(field "$o/script/result.json" nodes.list.1)"
n=$("$PATINA" log events "$o/script" --types node | grep -c '"event":"pause","name":"b".*"by":"script"')
[ "$n" = 3 ] || die "pause events of b: $n"

# The seed's pauses of b.
seed="--config $o/b.toml --fault pause-gap-ms=2000..6000@b --fault pause-ms=500..3000@b"
verify_ok "$o/seed" 3 3 $seed -- python3 /guest/pause.py driver seed 30
sed 's/^/    /' "$o/seed/run-0/inc-0/stdout"
r=$o/seed/run-0
p=$(field "$r/result.json" nodes.list.1.pauses)
[ "$p" -ge 2 ] || die "the seed's pauses of b: $p"
[ "$(field "$r/result.json" faults.counts.pause.injected)" = "$p" ] || die "faults.counts.pause: $(field "$r/result.json" faults.counts)"
n=$("$PATINA" log events "$r" --types node | grep -c '"event":"resume","name":"b".*"by":"seed"')
[ "$n" -ge $((p - 1)) ] || die "resume events of b: $n of $p pauses"
"$PATINA" replay "$r" >"$o/replay.txt" 2>&1 || { tail -5 "$o/replay.txt"; die "replay of a run with pauses"; }
echo "seed: $p pauses of b, $(field "$r/result.json" nodes.list.1.paused_ms) ms paused; replayed identically"

# A pause with no resume, the driver waiting on b: liveness, naming b.
c=$(run "$o/stuck" 1 --config "$o/b.toml" -- python3 /guest/pause.py driver stuck)
m=$(field "$o/stuck/result.json" message)
[ "$c" = liveness ] && grep -q 'paused: b (by script' <<<"$m" || die "a pause with no resume: $c: $m"
echo "no resume: $c: $m"

# Refused: the pause keys without nodes and for the driver.
st=0; "$PATINA" run --out "$o/none" --fault pause-gap-ms=1000..2000 -- /bin/true >/dev/null 2>"$o/none.err" || st=$?
[ "$st" != 0 ] && grep -q 'pause-gap-ms' "$o/none.err" || die "pause-gap-ms without nodes: $(cat "$o/none.err")"
st=0; "$PATINA" run --out "$o/drv" --config "$o/b.toml" --fault pause-gap-ms=1000..2000@driver -- /bin/true >/dev/null 2>"$o/drv.err" || st=$?
[ "$st" != 0 ] && grep -q 'pause-gap-ms' "$o/drv.err" || die "pause-gap-ms@driver: $(cat "$o/drv.err")"
echo "refused: pause-gap-ms without nodes and for the driver"
