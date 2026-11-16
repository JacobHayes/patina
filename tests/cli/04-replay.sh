# 4. `patina replay RUNDIR`: identical, with the run's exit status; `error` naming the program
#    after one byte of it changes; `nondeterministic` printing the first differing record when
#    the test hook perturbs one draw on replay; a run of another patina build refused.
#@ tier=quick budget=10
. "$(dirname "$0")/lib.inc"
d=$RUNS/prog
mkdir -p "$d"
cp "$PATINA_GUESTS/hello-static" "$d/hello"
chmod u+w "$d/hello"
# replay RUNDIR: sets $st, output in RUNDIR.replay.txt
replay() {
    st=0
    timeout 60 "$PATINA" replay "$1" >"$1.replay.txt" 2>&1 || st=$?
}
for want in ok failure; do
    case $want in ok) cmd="$d/hello" ;; failure) cmd="/bin/sh -c 'exit 3'" ;; esac
    eval "prun \"\$RUNS/$want\" --seed 7 -- $cmd"
    rst=$st
    replay "$RUNS/$want"
    [ "$st" = "$rst" ] || die "replay of $want: exit $st, the run exited $rst ($(tail -3 "$RUNS/$want.replay.txt"))"
    grep -q '^identical' "$RUNS/$want.replay.txt" || die "replay of $want: $(cat "$RUNS/$want.replay.txt")"
    [ "$(field "$RUNS/$want/replay/result.json" digest)" = "$(field "$RUNS/$want/result.json" digest)" ] || die "replay of $want: digest"
    echo "replay of $want: identical, exit $st"
done
# The planted divergence.
PATINA_TEST_REPLAY_PERTURB=1 replay "$RUNS/ok"
[ "$st" = "$(exit_of nondeterministic)" ] || die "perturbed replay: exit $st ($(tail -3 "$RUNS/ok.replay.txt"))"
[ "$(field "$RUNS/ok/replay/result.json" outcome)" = nondeterministic ] || die "perturbed replay: outcome"
grep -q 'record' "$RUNS/ok.replay.txt" || die "perturbed replay: no record printed"
echo "perturbed replay: nondeterministic, $(grep -m1 record "$RUNS/ok.replay.txt")"
# A run made by another patina build: replay and `run --config RUNDIR/run.json` refuse it
# before running anything.
cp -r "$RUNS/ok" "$RUNS/other"
python3 -I -c 'import json,sys; p=sys.argv[1]; r=json.load(open(p)); r["patina"]="0.0.1 "+"0"*64; json.dump(r,open(p,"w"))' "$RUNS/other/run.json"
st=0; timeout 60 "$PATINA" replay "$RUNS/other" --out "$RUNS/other-replay" >"$RUNS/other.txt" 2>&1 || st=$?
[ "$st" = "$(exit_of error)" ] || die "other build, replay: exit $st ($(cat "$RUNS/other.txt"))"
prun "$RUNS/other-run" --config "$RUNS/other/run.json"
[ "$st" = "$(exit_of error)" ] || die "other build, run --config: exit $st ($(cat "$RUNS/other-run.txt"))"
for x in other-replay other-run; do [ ! -e "$RUNS/$x" ] || die "other build: $x was made"; done
echo "other build: refused before running: $(head -1 "$RUNS/other.txt")"
# One byte of the program changes.
printf '\001' | dd of="$d/hello" bs=1 seek=1000 conv=notrunc status=none
replay "$RUNS/ok"
[ "$st" = "$(exit_of error)" ] || die "changed program: exit $st"
grep -qF -e "$d/hello" -e "$(realpath "$d/hello")" "$RUNS/ok.replay.txt" || die "changed program: file not named: $(cat "$RUNS/ok.replay.txt")"
echo "changed program: exit $st: $(head -1 "$RUNS/ok.replay.txt")"
