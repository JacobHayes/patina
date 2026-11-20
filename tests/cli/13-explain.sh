# 13. `patina explain RUNDIR` on the acklog example's crash bug (the first violating seed of
#    1-20 under `--crash machine`): the observed replay is the run (its digest, and the
#    observations are in RUNDIR/explain, not in its boundary log); the story is shorter than the
#    event log; its crash line is at the run's crash and names a path the crash lost; its stop
#    event is the run's failed assertion (`log events --from N --to N`). A second explain reuses
#    the replay. A run of another build is refused.
#    Expected on the arm64 runner: about 3 s.
#@ tier=quick budget=20
. "$(dirname "$0")/lib.inc"
r=""
for s in $(seq 1 20); do
    prun "$RUNS/acklog-$s" --seed "$s" --crash machine -- "$PATINA_GUESTS/examples/acklog"
    if [ "$(field "$RUNS/acklog-$s/result.json" outcome)" = violation ]; then r=$RUNS/acklog-$s; break; fi
done
[ -n "$r" ] || die "acklog: no violation in seeds 1-20"
echo "acklog: seed $s violates: $(field "$r/result.json" message)"
st=0; timeout 60 "$PATINA" explain "$r" --format json >"$r.story" 2>"$r.err" || st=$?
[ "$st" = 0 ] || die "explain: exit $st ($(cat "$r.err"))"
lhs=$(field "$r/explain/result.json" digest); rhs=$(field "$r/result.json" digest)
[ "$lhs" = "$rhs" ] || die "the observed replay's digest differs"
obs=$(stat -c %s "$r/explain/inc-0/observe.log")
[ "$obs" -gt 0 ] || die "no observations"
cmp -s "$r/inc-0/boundary.log" "$r/explain/inc-0/boundary.log" || die "the observed replay's boundary log is not the run's"
"$PATINA" log events "$r" >"$r.events"
python3 -I - "$r" <<'EOF' || die "the story"
import json, sys
r = sys.argv[1]
story = [json.loads(l) for l in open(r + ".story")]
events = [json.loads(l) for l in open(r + ".events")]
result = json.load(open(r + "/result.json"))
lines = [l for l in story if l["kind"] not in ("outcome", "stop")]
assert len(lines) * 4 < len(events), (len(lines), len(events))
crash = next(e for e in events if e["type"] == "crash")
at = [l for l in lines if l["kind"] in ("crash", "unsynced") and l["seq"] == crash["seq"]]
assert at, "no crash line at the crash"
assert any(p in l["text"] for l in at for p in crash["lost"]["paths"]), at
stop = story[-1]
assert stop["kind"] == "stop", stop
label = result["message"].split(":")[0].strip()
print(f"story: {len(lines)} lines for {len(events)} events; stop at event {stop['seq']}; label {label}")
EOF
n=$(python3 -I -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1])][-1]["seq"])' "$r.story")
"$PATINA" log events "$r" --from "$n" --to "$n" | tail -1 >"$r.stop"
[ "$(field "$r.stop" type)" = sdk ] && [ "$(field "$r.stop" op)" = assert ] || die "the stop event is not an assertion: $(cat "$r.stop")"
case "$(field "$r/result.json" message)" in "$(field "$r.stop" label)"*) ;; *) die "the stop event is another assertion: $(cat "$r.stop")" ;; esac
echo "stop event $n: $(cat "$r.stop")"
# Again: the replay is reused (its result is not rewritten).
m=$(stat -c %Y.%y "$r/explain/result.json")
timeout 60 "$PATINA" explain "$r" >"$r.text"
m2=$(stat -c %Y.%y "$r/explain/result.json")
[ "$m2" = "$m" ] || die "the second explain replayed again"
# A run made by another patina build is refused before anything runs.
cp -r "$r" "$RUNS/other"
rm -rf "${RUNS:?}/other/explain"
python3 -I -c 'import json,sys; p=sys.argv[1]; r=json.load(open(p)); r["patina"]="0.0.1 "+"0"*64; json.dump(r,open(p,"w"))' "$RUNS/other/run.json"
st=0; timeout 60 "$PATINA" explain "$RUNS/other" >"$RUNS/other.txt" 2>&1 || st=$?
[ "$st" = "$(exit_of error)" ] || die "other build: exit $st ($(cat "$RUNS/other.txt"))"
[ ! -e "$RUNS/other/explain" ] || die "other build: an explain directory was made"
echo "other build: refused: $(head -1 "$RUNS/other.txt")"
