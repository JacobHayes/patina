# 25. A run's phases (tests/guests/nodes/phases.py): `--setup` starts a server in the
# background and exits; the main command puts records through it under `--faults disk,net`;
# `--finally` checks the server holds them. The server outlives the setup command; every fault
# event comes after the setup's end and before the main command's; the same seed gives the same
# run, replay and verify are identical across the three phases. A failing setup is an error
# (stop setup) showing its output; a main command that fails skips the final check; a failing
# final check is the finding (stop finally). A `--crash-points` sweep crashes only at points of
# the main phase, and each restart runs the setup again. About 10 s on the arm64 runner.
#@ tier=quick budget=30 slots=1
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/25; mkdir -p "$d"
srv=(--setup "python3 /guest/phases.py start")
n=20
fin=(--finally "python3 /guest/phases.py check $n 127.0.0.1")
work=(-- python3 /guest/phases.py work $n 127.0.0.1)

# window DIR: the run's fault and crash events all lie in a main phase (after the setup's end,
# before the main command's, in the same incarnation); prints how many there are.
window() {
    "$PATINA" log events "$1" --types inc,phase,fault,crash >"$1.ev" || die "log events $1"
    python3 -I - "$1.ev" <<'PY'
import json, sys
phase, n = "setup", 0
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e["type"] == "inc":
        phase = "setup"
    elif e["type"] == "phase":
        phase = e.get("next", "none")
    elif e["type"] in ("fault", "crash"):
        assert phase == "main", (phase, e)
        n += 1
print(n)
PY
}

# Setup, workload and final check under disk and network faults: seeds from a random start
# until a run has a fault event (a search; nearly every seed has one).
s0=$((RANDOM % 1000 + 1)); s=$s0; f=0
while [ $s -lt $((s0 + 16)) ]; do
    run "$d/w" $s --faults disk,net "${srv[@]}" "${fin[@]}" "${work[@]}"
    [ "$(class "$d/w")" = ok ] || die "seed $s: $(class "$d/w"): $(field "$d/w/result.json" message)"
    f=$(window "$d/w") || die "seed $s: a fault outside the main phase"
    [ "$f" = 0 ] || break
    s=$((s + 1))
done
[ "$f" -gt 0 ] || die "seeds $s0..$s: no fault event"
for p in setup main finally; do
    [ "$(field "$d/w/result.json" phases.$p.exit.status)" = 0 ] || die "seed $s: the $p command: $(field "$d/w/result.json" phases.$p)"
done
grep -q '^start: serving$' "$d/w/inc-0/stdout" && grep -q "^check: $n puts" "$d/w/inc-0/stdout" \
    || die "seed $s: $(cat "$d/w/inc-0/stdout")"
echo "seed $s: setup, main and finally exit 0; $f fault events, all in the main phase"

# The same seed: the same run; replay and verify identical across the phases.
run "$d/w2" $s --faults disk,net "${srv[@]}" "${fin[@]}" "${work[@]}"
a=$(field "$d/w/result.json" digest) b=$(field "$d/w2/result.json" digest)
[ "$a" = "$b" ] || die "seed $s: digests $a and $b"
a=$(field "$d/w/result.json" phases) b=$(field "$d/w2/result.json" phases)
[ "$a" = "$b" ] || die "seed $s: phase tables $a and $b"
"$PATINA" replay "$d/w" >"$d/replay.txt" 2>&1 || die "replay: $(tail -3 "$d/replay.txt")"
grep -q '^identical' "$d/replay.txt" || die "replay: $(cat "$d/replay.txt")"
verify "$d/v" $s 2 cpu,aslr --faults disk,net "${srv[@]}" "${fin[@]}" "${work[@]}"
echo "seed $s: the same run twice; replay and verify identical"

# A setup that fails: an error naming the setup, with its output; the main command never runs.
out=$("$PATINA" run --seed $s --out "$d/sf" --mount "$PATINA_GUESTS":/guest:copy \
    --setup "sh -c 'echo no-database-here >&2; exit 3'" "${fin[@]}" "${work[@]}" 2>&1) && die "a failed setup: exit 0"
[ "$(class "$d/sf")/$(field "$d/sf/result.json" stop)" = error/setup ] || die "a failed setup: $(class "$d/sf")"
[ "$(field "$d/sf/result.json" phases.setup.exit.status)" = 3 ] || die "a failed setup: $(field "$d/sf/result.json" phases)"
[ "$(field_opt "$d/sf/result.json" phases.main)" = - ] || die "a failed setup: the main command ran"
grep -q no-database-here <<<"$out" || die "a failed setup: its output not shown: $out"
echo "a failed setup: error (setup), its output shown, nothing else run"

# A main command that fails: its own failure, the final check skipped.
run "$d/mf" $s "${srv[@]}" "${fin[@]}" -- python3 /guest/phases.py check 1 127.0.0.1
[ "$(class "$d/mf")/$(field "$d/mf/result.json" stop)" = failure/exit ] || die "a failed main: $(class "$d/mf")"
[ "$(field "$d/mf/result.json" phases.finally.skipped)" = true ] || die "a failed main: $(field "$d/mf/result.json" phases)"
# A final check that fails: the finding, stop finally.
run "$d/ff" $s "${srv[@]}" --finally "python3 /guest/phases.py check 1 127.0.0.1" -- true
[ "$(class "$d/ff")/$(field "$d/ff/result.json" stop)" = failure/finally ] || die "a failed final check: $(class "$d/ff")"
# A final check killed by a signal: crash (finally), never ok.
run "$d/fk" $s --finally "sh -c 'kill -9 \$\$'" -- true
[ "$(class "$d/fk")/$(field "$d/fk/result.json" stop)" = crash/finally ] || die "a killed final check: $(class "$d/fk")"
echo "a failed main command skips the final check; a failed final check is failure (finally), a killed one crash (finally)"

# Crash points only in the main phase: each child crashes the machine at one of the main
# command's points; its restart runs the setup again (the server on the crashed disk), then the
# main command; the store is ok at every point.
rm -rf "${d:?}/cp"; st=0
timeout 300 "$PATINA" sweep --seeds $s --crash-points --faults crash -j 4 --keep all --out "$d/cp" \
    --mount "$PATINA_GUESTS":/guest:copy "${srv[@]}" --finally "python3 /guest/phases.py check 2 127.0.0.1" \
    -- python3 /guest/phases.py work 2 127.0.0.1 >"$d/cp.txt" 2>&1 || st=$?
[ "$st" = 0 ] || die "crash points: exit $st: $(tail -5 "$d/cp.txt")"
python3 -I - "$d/cp/report.json" <<'PY' || die "crash points"
import json, sys
br = json.load(open(sys.argv[1]))["crash_points"]
assert br["points"] > 0 and br["tried"] == br["points"], br
PY
for c in "$d"/cp/seed-*@*; do
    [ "$(window "$c")" = 1 ] || die "crash points: $c: a crash outside the main phase"
    [ "$(grep -c '^start: serving$' "$c/inc-1/stdout")" = 1 ] || die "crash points: $c: the restart did not run the setup"
done
echo "crash points: $(field "$d/cp/report.json" crash_points.points), each in the main phase; ok at each"
