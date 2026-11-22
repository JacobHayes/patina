# 18. Machines: each machine's realtime clock. clock-skew-ms gives each boot of a machine an offset
# (here exactly 1 s, ahead or behind): the machine's realtime clock and the times it writes on
# its files carry it, its monotonic clock does not, main's (here `faults = false`) has none; result.json
# and the events show each machine's skew. `clock NAME` (tests/guests/machines/clockstep.c) moves a
# machine's clock as setting the clock does on Linux (clock_nanosleep(2), timerfd_create(2)):
# absolute realtime sleeps, condition-variable waits and timerfds move with it (a +5 s step
# at 1 s fires timers due at 10 s at 5 s; a -5 s step at 20 s moves one due at 22 s to 27 s),
# relative ones on any clock do not, and a timerfd with TFD_TIMER_CANCEL_ON_SET reads
# ECANCELED at the step. Both are identical under verify --vary cpu,load,aslr,sandbox,repeat
# and replay. Main's clock is skewed as a machine's is; without machines the clock key is refused.
#@ tier=quick budget=40 slots=2.5
# arm64 (CI runner): about 8 s.
. "$(dirname "$0")/lib.inc"
o=$RUNS/18-clock; mkdir -p "$o"

# The skew: realtime minus monotonic, and a file's mtime minus realtime, on each machine.
show="import time, os; g = time.time() - time.monotonic(); open('f', 'w').close(); print(round(g, 3), round(os.stat('f').st_mtime - time.time(), 1))"
: >"$o/skew.toml"
for n in a b; do conf "$o/skew.toml" "$n" python3 -c "$show"; done
driver "$o/skew.toml"
verify_ok "$o/skew" 1 3 --config "$o/skew.toml" --fault clock-skew-ms=1000..1000 -- python3 -c "$show"
r=$o/skew/run-0
d=$(cut -d' ' -f1 "$r/boot-1/stdout")
for n in a b; do
    read -r g m <"$r/machine/$n/boot-1/stdout"
    s=$(field "$r/result.json" "machines.list.$([ $n = a ] && echo 1 || echo 2).clock.skew_ms.0")
    python3 -I -c 'import sys; d, g, s, m = map(float, sys.argv[1:5]); sys.exit(0 if abs(g - d - s / 1000) < 0.01 and abs(s) == 1000 and abs(m) <= 0.1 else 1)' "$d" "$g" "$s" "$m" \
        || die "machine $n: realtime - monotonic $g against main's $d, skew $s ms, mtime - realtime $m"
    echo "machine $n: skew $s ms: realtime - monotonic $g s (main $d s), its file's mtime agrees with its clock"
done
n=$("$PATINA" log events "$r" --types machine | grep -c '"event":"clock".*"by":"seed"')
[ "$n" = 2 ] || die "clock events: $n"

# The steps.
: >"$o/step.toml"; conf "$o/step.toml" b /guest/clockstep machine
verify_ok "$o/step" 1 3 --config "$o/step.toml" -- /guest/clockstep main
r=$o/step/run-0
sed 's/^/    /' "$r/machine/b/boot-1/stdout"
want="tfd-cancel: 1000 ms, Operation canceled
cond: 5000 ms, Connection timed out
tfd-cancel: 5000 ms, 0
tfd-abs: 5000 ms, 0
abs-sleep: 5000 ms, 0
rel-sleep: 10000 ms, 0
tfd-rel: 10000 ms, 0
tfd-mono: 10000 ms, 0
abs-back: 27000 ms, 0
realtime - monotonic: +5000 ms after the first step, +0 ms after the second"
got=$(sort "$r/machine/b/boot-1/stdout"); want=$(sort <<<"$want")
[ "$got" = "$want" ] || die "the timers across steps: $(cat "$r/machine/b/boot-1/stdout")"
[ "$(field "$r/result.json" machines.list.1.clock.steps)" = 2 ] || die "result.json: $(field "$r/result.json" machines.list.1)"
"$PATINA" replay "$r" >"$o/replay.txt" 2>&1 || { tail -5 "$o/replay.txt"; die "replay of a run with clock steps"; }
echo "steps: the timers fired as Linux documents; replayed identically"

# Main's skew: its realtime clock carries it, as a machine's does.
run_ok "$o/main" 1 --config "$o/step.toml" --fault clock-skew-ms=1000..1000@main -- python3 -c "$show"
read -r g _ <"$o/main/boot-1/stdout"
s=$(field "$o/main/result.json" machines.list.0.clock.skew_ms.0)
python3 -I -c 'import sys; g, d, s = map(float, sys.argv[1:4]); sys.exit(0 if abs(g - d - s / 1000) < 0.01 and abs(s) == 1000 else 1)' "$g" "$d" "$s" \
    || die "main: realtime - monotonic $g against $d unskewed, skew $s ms"
echo "main: skew $s ms: realtime - monotonic $g s"
# Refused: the clock key without machines.
st=0; "$PATINA" run --out "$o/none" --fault clock-skew-ms=0..10 -- /bin/true >/dev/null 2>"$o/none.err" || st=$?
[ "$st" != 0 ] && grep -q 'clock-skew-ms' "$o/none.err" || die "clock-skew-ms without machines: $(cat "$o/none.err")"
echo "refused: clock-skew-ms without machines"
