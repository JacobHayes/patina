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

wait "$hang" || true
is hang "$(cat hang.rc)" 2 error check
echo "ok: kvlog found, replayed and minimised; failing checkers are errors; the alternating one is check-unstable"
