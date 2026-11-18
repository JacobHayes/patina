# 1. `--check`: a checker outside the simulation judges each run that ended ok.
#    kvlog (no SDK; acknowledges records it never syncs) under machine crashes with
#    examples/checks/acked-kept: one finding group, `violation check: acked-record-lost`,
#    replayed identical, minimised with the crash kept; `kvlog fixed` has none; the checker
#    run by hand on the run directory says the same; the sweep resumes, and a changed checker
#    file replaces it. A checker that exits 2, cannot be started, is missing or outlives
#    --timeout is never a pass (`error`, exit 2); one whose verdict alternates makes the replay
#    `error check-unstable`, not `nondeterministic`; a run that ends failure, crash or liveness
#    does not start it; a path in the run directory in a finding replays the same; a passing checker leaves the run's outcome, digest and logs as a run
#    without --check has them.
# 2. The report: a `check:` line that counts each verdict; a check that judged no run makes the
#    sweep vacuous (`--allow-unmet check` allows it); `--allow-unmet 'lib-*'` allows by pattern.
#    A finding named by its label is one group over every case it appears in; two tests that
#    exit 1 with the same last line stay two. `--known`: the first matching line names a
#    finding, known findings do not fail the sweep, `[*planted*]` selects by case, and a `!`
#    entry that matched no run makes the report vacuous.
#@ tier=quick budget=10 slots=4
set -eu
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
kv=$PATINA_GUESTS/examples/kvlog hello=$PATINA_GUESTS/hello-static
die() { echo "FAIL: $*"; exit 1; }
cd "$RUNS"
mkdir chk
# Checkers, each a file: the run directory is their last argument.
printf '#!/bin/sh\necho "broken: this checker fails"\nexit 2\n' >chk/exit2
printf '#!/nonexistent/interpreter\n' >chk/unstartable
printf '#!/bin/sh\nexec tail -f /dev/null\n' >chk/hang
printf '#!/bin/sh\n: >"$(dirname "$0")/ran"\n' >chk/mark
# Alternates between a finding and a pass: its state is outside the run directory.
printf '#!/bin/sh\nf=$(dirname "$0")/flip.state\nif [ -f "$f" ]; then rm "$f"; exit 0; fi\n: >"$f"; echo "flaky: odd call"; exit 1\n' >chk/flip
# A finding that names a file in the run directory, which a replay has elsewhere.
printf '#!/bin/sh\necho "path-in-finding: $1/inc-0/stdout is wrong"\nexit 1\n' >chk/path
cp "$root/examples/checks/acked-kept" chk/acked
chmod +x chk/*

# run NAME [options] -- CMD: `patina run` into NAME with JSON output; prints its exit status
run() {
    n=$1; shift
    rc=0
    "$PATINA" run --out "$n" --format json "$@" >"$n.json" 2>"$n.err" || rc=$?
    echo "$rc"
}
# is NAME RC OUTCOME STOP: the run's exit status and its outcome and stop
is() {
    got="$2 $(jq -r '"\(.outcome) \(.stop)"' "$1.json")"
    [ "$got" = "$3 $4 $5" ] || die "$1: want exit $3, $4 $5; got $got: $(tail -c 300 "$1.err")"
}

# Beside the rest: a checker still running after --timeout.
(run hang --timeout 2 --check chk/hang -- "$hello" >hang.rc) &
hang=$!

# The kvlog sweep, and kvlog fixed.
rc=0
"$PATINA" sweep --seeds 1..30 -j 4 --crash machine:10 --out kv --check chk/acked -- "$kv" >kv.txt 2>&1 || rc=$?
[ "$rc" = 1 ] || die "kvlog sweep: exit $rc: $(tail -3 kv.txt)"
groups=$(jq -r '[.groups[].signature] | join(" | ")' kv/report.json)
case $groups in "violation check: acked-record-lost"*) ;; *) die "kvlog sweep: groups: $groups" ;; esac
[ "$(jq '.groups | length' kv/report.json)" = 1 ] || die "kvlog sweep: more than one group: $groups"
[ "$(jq -r '.groups[0].replay.result' kv/report.json)" = identical ] || die "kvlog: the first seed's replay: $(jq -c .groups[0].replay kv/report.json)"
first=$(jq -r '.groups[0].first.dir' kv/report.json)
echo "kvlog: $(jq -r .findings kv/report.json) of 30 runs: $groups (first $first)"
rc=0
"$PATINA" sweep --seeds 1..30 -j 4 --crash machine:10 --out kvf --check chk/acked -- "$kv" fixed >kvf.txt 2>&1 || rc=$?
[ "$rc" = 0 ] && [ "$(jq '.groups | length' kvf/report.json)" = 0 ] || die "kvlog fixed: exit $rc: $(tail -3 kvf.txt)"
[ "$(jq '.outcomes.ok' kvf/report.json)" = 30 ] || die "kvlog fixed: not 30 ok runs"

# By hand, outside patina, the checker says what it said in the run.
rc=0
line=$(PATINA_SEED=$(jq -r .seed "$first/result.json") PATINA_EXIT=0 chk/acked "$first") || rc=$?
want=$(jq -r '"\(.check.label): \(.check.detail)"' "$first/result.json")
[ "$rc" = 1 ] && [ "$line" = "$want" ] || die "by hand: exit $rc, '$line'; the run said '$want'"

# minimize keeps the crash and the signature; the checker runs in each try.
"$PATINA" minimize "$first" --out min --format json >min.json 2>min.err || die "minimize: $(tail -2 min.err)"
case $(jq -r .to min.json) in *"crash machine"*) ;; *) die "minimize dropped the crash: $(jq -c . min.json)" ;; esac
[ "$(jq -r .signature "$(jq -r .dir min.json)/result.json")" = "$(jq -r .signature "$first/result.json")" ] || die "minimize: another signature"

# The same sweep resumes (a kept run stays); with the checker's file changed it is replaced.
: >"$first/kept"
"$PATINA" sweep --seeds 1..30 -j 4 --crash machine:10 --out kv --check chk/acked -- "$kv" >kv2.txt 2>&1 || true
[ -f "$first/kept" ] || die "the same sweep did not resume"
echo "# changed" >>chk/acked
"$PATINA" sweep --seeds 1..30 -j 4 --crash machine:10 --out kv --check chk/acked -- "$kv" >kv3.txt 2>&1 || true
[ ! -f "$first/kept" ] || die "a changed checker did not replace the sweep"

# A checker that fails is never a pass.
is exit2 "$(run exit2 --check chk/exit2 -- "$hello")" 2 error check
is unstartable "$(run unstartable --check chk/unstartable -- "$hello")" 2 error check
rc=$(run missing --check chk/no-such-checker -- "$hello")
[ "$rc" = 2 ] && [ "$(jq -r .outcome missing.json)" = error ] && [ ! -e missing/result.json ] || die "a missing checker: exit $rc: $(cat missing.err)"

# An alternating checker: the replay's logs are identical and its verdict is not.
is flip "$(run flip --check chk/flip -- "$hello")" 1 violation check
rc=0
"$PATINA" replay flip --format json >flip-replay.json 2>flip-replay.err || rc=$?
got="$rc $(jq -r '"\(.outcome) \(.stop)"' flip-replay.json)"
[ "$got" = "2 error check-unstable" ] || die "alternating checker: replay $got"

# A path in the run directory does not make the replay's verdict differ.
is path "$(run path --check chk/path -- "$hello")" 1 violation check
rc=0
"$PATINA" replay path --format json >path-replay.json 2>path-replay.err || rc=$?
got="$rc $(jq -r '"\(.outcome) \(.stop)"' path-replay.json)"
[ "$got" = "1 violation check" ] || die "a run-directory path in a finding: replay $got"

# Runs that did not end ok do not start the checker; one that did, does.
is failed "$(run failed --check chk/mark -- /bin/sh -c 'exit 3')" 1 failure exit
is crashed "$(run crashed --check chk/mark -- /usr/bin/python3 -I -c 'import os; os.abort()')" 1 crash signal
is stuck "$(run stuck --time-limit 100 --check chk/mark -- "$PATINA_GUESTS/liveness")" 1 liveness time-limit
[ ! -e chk/ran ] || die "the checker ran after a run that did not end ok"
is marked "$(run marked --check chk/mark -- "$hello")" 0 ok exit
[ -e chk/ran ] || die "the checker did not run after an ok run"

# A passing checker leaves the run as a run without --check has it.
is plain "$(run plain -- "$hello")" 0 ok exit
[ "$(jq -r .digest plain.json)" = "$(jq -r .digest marked.json)" ] || die "the digest differs with --check"
cmp -s plain/inc-0/boundary.log marked/inc-0/boundary.log || die "the boundary log differs with --check"
[ "$(jq -r .check.verdict marked.json)" = pass ] && [ "$(jq -r .check plain.json)" = null ] || die "check verdicts: $(jq -c .check marked.json) $(jq -c .check plain.json)"

# The check: line. Every run that ended ok was judged or not judged, and a run without a crash
# is not judged for the checker's own reason; a sweep in which no run was judged is vacuous.
ran=$(cat kv/seed-*/result.json | jq -sc '[map(select(.check.verdict == "pass")), map(select(.check.verdict == "fail")), map(select(.check.verdict == "not-judged"))] | map(length)')
said=$(jq -c '.check | [.passed, .failed, ([.not_judged[]] | add // 0)]' kv/report.json)
[ "$ran" = "$said" ] && [ "$(jq '.check.not_judged["no crash in this run"]' kv/report.json)" -gt 0 ] || die "check: line: pass, fail, not judged $said; the runs' verdicts $ran"
grep -q '^check: judged ' kv.txt || die "the kvlog sweep printed no check: line"
rc=0
"$PATINA" sweep --seeds 1..4 -j 4 --out kvn --check chk/acked -- "$kv" >kvn.txt 2>&1 || rc=$?
[ "$rc" = 2 ] && [ "$(jq -r '.check.vacuous' kvn/report.json)" = true ] || die "a check that judged nothing: exit $rc: $(tail -3 kvn.txt)"
[ "$(jq -r '.check.not_judged | keys[0]' kvn/report.json)" = "no crash in this run" ] || die "not judged reasons: $(jq -c .check kvn/report.json)"
rc=0
"$PATINA" report --allow-unmet check kvn >/dev/null || rc=$?
[ "$rc" = 0 ] || die "--allow-unmet check: exit $rc"

# --allow-unmet patterns: unmet sometimes labels lib-a, lib-b and app-c.
run sdk --mount "$root/sdk/python:/sdk" -- /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, "/sdk"); import patina
for l in ("lib-a", "lib-b", "app-c"): patina.Sometimes(l).check(False)' >/dev/null
unmet() { rc=0; "$PATINA" report --format json "$@" sdk >unmet.json || rc=$?; echo "$rc $(jq -r '.sdk.sometimes_never_held | join(",")' unmet.json)"; }
[ "$(unmet --allow-unmet 'lib-*')" = "2 app-c" ] || die "--allow-unmet 'lib-*': $(unmet --allow-unmet 'lib-*')"
[ "$(unmet --allow-unmet 'lib-*' --allow-unmet app-c)" = "0 " ] || die "--allow-unmet 'lib-*' app-c: $(unmet --allow-unmet 'lib-*' --allow-unmet app-c)"
[ "$(unmet --allow-unmet '*')" = "0 " ] || die "--allow-unmet '*': $(unmet --allow-unmet '*')"
[ "$(jq -r '.allowed_unmet | length' unmet.json)" = 3 ] || die "allowed unmet labels are not listed: $(jq -c .allowed_unmet unmet.json)"

# Grouping across cases and known findings. calc OP A B has two planted bugs (sub clamps at 0,
# mul by 0 gives A); the checker names a wrong answer wrong-OP, so each bug is one group over
# every case that reaches it.
mkdir calc
printf '%s\n' '#!/bin/sh' 'case $1 in' 'add) echo $(($2 + $3)) ;;' \
  'sub) r=$(($2 - $3)); [ "$r" -lt 0 ] && r=0; echo $r ;;' \
  'mul) if [ "$3" = 0 ]; then echo "$2"; else echo $(($2 * $3)); fi ;;' 'esac' >calc/calc
printf '%s\n' '#!/bin/sh' 'd=$1' 'set -- $PATINA_CASE' 'shift 2' \
  'case $1 in add) w=$(($2 + $3)) ;; sub) w=$(($2 - $3)) ;; mul) w=$(($2 * $3)) ;; esac' \
  'g=$(cat "$d/inc-0/stdout")' '[ "$g" = "$w" ] && exit 0' 'echo "wrong-$1: got $g, want $w"' 'exit 1' >chk/calc
chmod +x chk/calc
for c in "add 1 2" "sub 1 5" "mul 3 0" "add 4 4" "sub 2 9" "mul 5 0" "sub 9 1" "mul 2 2" "sub 3 7 planted"; do
  echo "/bin/sh /calc/calc $c"
done >calc.txt
calc() { n=$1; shift; rc=0; "$PATINA" sweep --seeds 1..2 -j 4 --cases calc.txt --mount "$RUNS/calc:/calc" --out "$n" --check chk/calc "$@" >"$n.txt" 2>&1 || rc=$?; echo "$rc"; }
rc=$(calc calcs)
[ "$rc" = 1 ] || die "calc sweep: exit $rc: $(tail -3 calcs.txt)"
[ "$(jq '[.groups[] | select(.run_outcome == "violation")] | length' calcs/report.json)" = 2 ] || die "calc sweep: groups $(jq -c '[.groups[] | [.signature, .cases]]' calcs/report.json)"
[ "$(jq '[.groups[] | select((.cases | length) < 2)] | length' calcs/report.json)" = 0 ] || die "calc sweep: a group over one case: $(jq -c '[.groups[] | [.signature, .cases]]' calcs/report.json)"
calc_groups=$(jq -r '[.groups[] | "\(.signature) (\(.cases | length) cases)"] | join("; ")' calcs/report.json)
# Known: the first matching line names a run; [*planted*] selects by the case line.
printf '%s\n' '!planted [*planted*] violation check: wrong-sub*' 'clamp violation check: wrong-sub: *' 'fixed violation check: wrong-add*' >known1
cp known1 known2; echo 'mul-zero violation check: wrong-mul: *' >>known2
kn() { rc=0; "$PATINA" report --format json --known "$@" >kn.json || rc=$?; echo "$rc $(jq -r '[.known.entries[] | "\(.id)=\(.count)"] | join(" ")' kn.json) new=$(jq '[.groups[] | select(.known == null)] | length' kn.json)"; }
[ "$(kn known1 calcs)" = "1 planted=2 clamp=4 fixed=0 new=1" ] || die "known file without mul-zero: $(kn known1 calcs)"
[ "$(kn known2 calcs)" = "0 planted=2 clamp=4 fixed=0 mul-zero=4 new=0" ] || die "known file naming both: $(kn known2 calcs)"
# The sweep with the known file says what the report over its runs says.
[ "$(calc calcs --known known2)" = 0 ] && [ "$(kn known2 calcs | cut -c1)" = 0 ] || die "sweep --known: $(tail -3 calcs.txt)"
grep -q '^known: .*none new' calcs.txt || die "sweep --known printed no known: line: $(cat calcs.txt)"
# Without the planted case's runs, the !planted entry makes the report vacuous.
rc=0
"$PATINA" report --known known2 $(ls -d calcs/seed-*/* | grep -v planted) >noplant.txt || rc=$?
[ "$rc" = 2 ] && grep -q '!planted matched no run' noplant.txt || die "without the planted case: exit $rc: $(cat noplant.txt)"
# Two tests that exit 1 with the same last line stay two groups.
printf '%s\n' "/bin/sh -c 'echo boom >&2; exit 1' first" "/bin/sh -c 'echo boom >&2; exit 1' second" >two.txt
"$PATINA" sweep --seeds 1 --cases two.txt --out two >two.out 2>&1 || true
[ "$(jq '.groups | length' two/report.json)" = 2 ] || die "two failing tests: $(jq -c '[.groups[] | [.signature, .cases]]' two/report.json)"
echo "calc: $calc_groups; known: $(kn known1 calcs)"
echo "check: $(jq -c .check kv/report.json); without crashes: vacuous"

wait "$hang" || true
is hang "$(cat hang.rc)" 2 error check
echo "ok: kvlog found, replayed and minimised; failing checkers are errors; the alternating one is check-unstable"
