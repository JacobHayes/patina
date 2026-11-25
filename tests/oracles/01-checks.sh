# 1. `--check`: a checker outside the simulation judges each run that ended ok.
#    kvlog (no SDK; acknowledges records it never syncs) under machine crashes with
#    examples/checks/acked-kept: one finding group, `violation check: acked-record-lost`,
#    replayed identical, minimised with the crash kept; the checker run by hand on the run
#    directory says the same (`kvlog fixed`, and resuming a sweep: 02-sweeps.sh). A checker that exits 2, cannot be started, is missing or outlives
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
# 3. `--ok-exit` and `patina inspect tree`: upcase (a short write gives the wrong file and exit 0)
#    swept with disk faults against a faults-off reference run with `--ok-exit 1 --check
#    same-tree`: one `wrong-output` group with fs-short in every run and no failure (the plain
#    sweep and `upcase fixed`: 02-sweeps.sh). An --ok-exit status the program did not exit with is
#    still a failure, as is a listed status after an INVARIANT line, and a signal still a
#    crash; the rerun line and run.json carry the list. `log tree` writes the tree the guest ended with (not the one it started from) and works
#    on every boot of a crashed run.
# 4. `patina inspect events`: a file created as a/x and renamed to b/y is named a/x before the
#    rename and b/y after it, under --disk's guest location; one line per trap record; two runs
#    of one seed give the same bytes. examples/checks/confined and synced-before-mark, which
#    read it, find their planted bugs over a seed range through --check and pass the fixes
#    (marklog fixed marks progress before its fsync: only the `ack` marks are judged). An open
#    through a symlink has its path as passed and the path it walked, the
#    same in five runs under cpu and aslr variation.
# 6. `patina recheck`: the same checker leaves each kept run's result.json byte for byte; a
#    keyed finding (LABEL [KEY]: detail) is grouped by its key, and shown as written.
# Quick tier: 1, 2, 3 and 6 (about 4 s on the arm64 runner); 4 and 5 in the area tier.
#@ tier=quick budget=10 slots=2
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
printf '#!/bin/sh\necho "path-in-finding: $1/boot-1/stdout is wrong"\nexit 1\n' >chk/path
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
(run hang --config "$("$PATINA_CFG" check-timeout=2)" --check chk/hang -- "$hello" >hang.rc) &
hang=$!

# The kvlog sweep (about one seed in four violates, which ones depending on the host), and
# kvlog fixed.
rc=0
"$PATINA" sweep --seeds 1..64 -j 4 --fault crash-permille=10 --out kv --check chk/acked -- "$kv" >kv.txt 2>&1 || rc=$?
[ "$rc" = 1 ] || die "kvlog sweep: exit $rc: $(tail -3 kv.txt)"
groups=$(jq -r '[.groups[].signature] | join(" | ")' kv/report.json)
case $groups in "violation check: acked-record-lost"*) ;; *) die "kvlog sweep: groups: $groups" ;; esac
[ "$(jq '.groups | length' kv/report.json)" = 1 ] || die "kvlog sweep: more than one group: $groups"
[ "$(jq -r '.groups[0].replay.result' kv/report.json)" = identical ] || die "kvlog: the first seed's replay: $(jq -c .groups[0].replay kv/report.json)"
first=$(jq -r '.groups[0].first.dir' kv/report.json)
echo "kvlog: $(jq -r .findings kv/report.json) of 64 runs: $groups (first $first)"

# By hand, outside patina, the checker says what it said in the run.
rc=0
line=$(PATINA_SEED=$(jq -r .seed "$first/result.json") PATINA_EXIT=0 chk/acked "$first") || rc=$?
want=$(jq -r '"\(.check.label): \(.check.detail)"' "$first/result.json")
[ "$rc" = 1 ] && [ "$line" = "$want" ] || die "by hand: exit $rc, '$line'; the run said '$want'"

# minimize keeps the crash and the signature; the checker runs in each try.
"$PATINA" minimize "$first" --out min --format json >min.json 2>min.err || die "minimize: $(tail -2 min.err)"
case $(jq -r .to min.json) in *crash-permille=*) ;; *) die "minimize dropped the crash: $(jq -c . min.json)" ;; esac
lhs=$(jq -r .signature "$(jq -r .dir min.json)/result.json"); rhs=$(jq -r .signature "$first/result.json")
[ "$lhs" = "$rhs" ] || die "minimize: another signature"

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
is stuck "$(run stuck --config $("$PATINA_CFG" time-limit=100) --check chk/mark -- "$PATINA_GUESTS/liveness")" 1 liveness time-limit
[ ! -e chk/ran ] || die "the checker ran after a run that did not end ok"
is marked "$(run marked --check chk/mark -- "$hello")" 0 ok exit
[ -e chk/ran ] || die "the checker did not run after an ok run"

# A passing checker leaves the run as a run without --check has it.
is plain "$(run plain -- "$hello")" 0 ok exit
lhs=$(jq -r .digest plain.json); rhs=$(jq -r .digest marked.json)
[ "$lhs" = "$rhs" ] || die "the digest differs with --check"
cmp -s plain/boot-1/boundary.log marked/boot-1/boundary.log || die "the boundary log differs with --check"
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
"$PATINA" inspect summary --allow-unmet check kvn >/dev/null || rc=$?
[ "$rc" = 0 ] || die "--allow-unmet check: exit $rc"

# --allow-unmet patterns: unmet sometimes labels lib-a, lib-b and app-c.
run sdk --mount "$root/sdk/python:/sdk" -- /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, "/sdk"); import patina
for l in ("lib-a", "lib-b", "app-c"): patina.Sometimes(l).check(False)' >/dev/null
unmet() { rc=0; "$PATINA" inspect summary --format json "$@" sdk >unmet.json || rc=$?; echo "$rc $(jq -r '.sdk.sometimes_never_held | join(",")' unmet.json)"; }
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
  'g=$(cat "$d/boot-1/stdout")' '[ "$g" = "$w" ] && exit 0' 'echo "wrong-$1: got $g, want $w"' 'exit 1' >chk/calc
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
kn() { rc=0; "$PATINA" inspect summary --format json --known "$@" >kn.json || rc=$?; echo "$rc $(jq -r '[.known.entries[] | "\(.id)=\(.count)"] | join(" ")' kn.json) new=$(jq '[.groups[] | select(.known == null)] | length' kn.json)"; }
[ "$(kn known1 calcs)" = "1 planted=2 clamp=4 fixed=0 new=1" ] || die "known file without mul-zero: $(kn known1 calcs)"
[ "$(kn known2 calcs)" = "0 planted=2 clamp=4 fixed=0 mul-zero=4 new=0" ] || die "known file naming both: $(kn known2 calcs)"
# The sweep with the known file says what the report over its runs says.
[ "$(calc calcs --known known2)" = 0 ] && [ "$(kn known2 calcs | cut -c1)" = 0 ] || die "sweep --known: $(tail -3 calcs.txt)"
grep -q '^known: .*none new' calcs.txt || die "sweep --known printed no known: line: $(cat calcs.txt)"
# Without the planted case's runs, the !planted entry makes the report vacuous.
rc=0
"$PATINA" inspect summary --known known2 $(ls -d calcs/seed-*/* | grep -v planted) >noplant.txt || rc=$?
[ "$rc" = 2 ] && grep -q '!planted matched no run' noplant.txt || die "without the planted case: exit $rc: $(cat noplant.txt)"
# Two tests that exit 1 with the same last line stay two groups.
printf '%s\n' "/bin/sh -c 'echo boom >&2; exit 1' first" "/bin/sh -c 'echo boom >&2; exit 1' second" >two.txt
"$PATINA" sweep --seeds 1 --cases two.txt --out two >two.out 2>&1 || true
[ "$(jq '.groups | length' two/report.json)" = 2 ] || die "two failing tests: $(jq -c '[.groups[] | [.signature, .cases]]' two/report.json)"
echo "calc: $calc_groups; known: $(kn known1 calcs)"
echo "check: $(jq -c .check kv/report.json); without crashes: vacuous"

# 3. --ok-exit and log tree. Disk faults with fs errors at 10 per mille: under the disk class alone
# about one seed in twenty exits 1, too few in 80 for which seeds those are not to decide it.
up=$PATINA_GUESTS/examples/upcase same=$root/examples/checks/same-tree
export PATINA
"$PATINA" run --seed 1 --out upref -- "$up" >upref.txt 2>&1 || die "upcase reference: $(tail -2 upref.txt)" # lint-allow: seed — faults off, upcase writes the same tree on every seed
rc=0
"$PATINA" sweep --seeds 1..80 -j 4 --faults disk --fault fs-error-permille=10 --ok-exit 1 --check "$same upref" --out up1 -- "$up" >up1.txt 2>&1 || rc=$?
[ "$rc" = 1 ] && [ "$(jq '.groups | length' up1/report.json)" = 1 ] || die "upcase checked sweep: exit $rc: $(tail -3 up1.txt)"
case $(jq -r '.groups[0].signature' up1/report.json) in "violation check: wrong-output"*) ;; *) die "upcase: $(jq -c '.groups[0]' up1/report.json)" ;; esac
jq -e '.groups[0].faults.every | index("fs-short")' up1/report.json >/dev/null || die "upcase: fs-short is not in every failing run"
[ "$(jq '.ok_exit // 0' up1/report.json)" -gt 0 ] || die "upcase: no run counted as a clean failure"
echo "upcase: checked: $(jq -r '"\(.findings) \(.groups[0].signature)"' up1/report.json)"
# Only the statuses named, never a signal; the rerun line and run.json carry the list.
is okexit "$(run okexit --ok-exit 1,3 -- /bin/sh -c 'exit 3')" 0 ok ok-exit
is okexit2 "$(run okexit2 --ok-exit 1,3 -- /bin/sh -c 'exit 2')" 1 failure exit
is okexitinv "$(run okexitinv --ok-exit 1 -- /bin/sh -c 'echo "INVARIANT kept: no" >&2; exit 1')" 1 failure exit
is okexitsig "$(run okexitsig --ok-exit 1,134 -- /usr/bin/python3 -I -c 'import os; os.abort()')" 1 crash signal
printf '#!/bin/sh\necho "exited: status $PATINA_EXIT"\nexit 1\n' >chk/exited && chmod +x chk/exited
"$PATINA" sweep --seeds 1..1 --ok-exit 3 --check chk/exited --out okx -- /bin/sh -c 'exit 3' >okx.txt 2>&1 || true
rerun=$(jq -r '.groups[0].rerun' okx/report.json)
rc=0
eval "\"\$PATINA\" run --out okx-rerun --format json ${rerun#patina run }" >okx-rerun.json 2>/dev/null || rc=$?
[ "$rc $(jq -r .outcome okx-rerun.json)" = "1 violation" ] || die "the rerun line ($rerun): exit $rc"
# log tree: the tree the guest ended with, against the guest's own listing of it.
mkdir lt-start && echo old >lt-start/gone && echo keep >lt-start/kept
list='find . -mindepth 1 -path ./listing -prune -o -printf "%p %y %m %l\n" | LC_ALL=C sort; find . -type f ! -name listing | LC_ALL=C sort | xargs cat'
run lt --disk lt-start -- /bin/sh -c "rm gone; mkdir -p d/e; echo new >d/f; chmod 640 d/f; ln -s d/f l; { $list; } >listing" >/dev/null
[ "$(jq -r .outcome lt.json)" = ok ] || die "log tree guest: $(tail -2 lt.err)"
"$PATINA" inspect tree lt/boot-1 lt-tree || die "log tree failed"
mv lt-tree/listing lt-listing
# lint-allow: plain-sh — the listing command the guest ran under /bin/sh, run the same way
lhs=$(cd lt-tree && sh -c "$list"); rhs=$(cat lt-listing)
[ "$lhs" = "$rhs" ] || die "log tree differs from the guest's own tree: $lhs"
! "$PATINA" inspect tree lt/boot-1 lt-tree 2>/dev/null || die "log tree wrote into a directory that is not empty"
# A sweep without a checker prunes the logs of its ok runs.
"$PATINA" sweep --seeds 1..2 --out prn -- "$hello" >prn.txt 2>&1 || die "sweep of hello: $(tail -2 prn.txt)"
pruned=$(for d in prn/seed-*; do [ -d "$d/boot-1" ] || { echo "$d"; break; }; done)
[ -n "$pruned" ] && ! "$PATINA" inspect tree "$pruned/boot-1" lt-pruned 2>/dev/null && [ ! -e lt-pruned ] || die "log tree of a pruned run '$pruned'"
# Every boot of a crashed run; each holds at least the records acknowledged in it.
n=0
for inc in "$first"/boot-*; do
    "$PATINA" inspect tree "$inc" "lt-$n" || die "log tree $inc"
    last=$(sed -n 's/^ack //p' "$inc/stdout" | tail -n1)
    [ $(($(wc -c <"lt-$n/data.log") / 8)) -gt "${last:--1}" ] || die "log tree $inc: fewer records than acknowledged"
    n=$((n + 1))
done
[ "$n" -gt 1 ] || die "the crashed run has one boot"
echo "log tree: $n boots of $first"

# 4. The event stream, and the example checks that read it.
# 4 and 5 run in the area tier only: a dozen more sweeps, which the quick tier's budget does not
# hold on a shared runner (5 to 7 s of 10 there, and over it beside a busy neighbour).
if [ "${CHECK_TIER:-}" != quick ]; then
files=$PATINA_GUESTS/oracles-files marklog=$PATINA_GUESTS/oracles-marklog
mkdir app
(
    for v in other data; do
        "$PATINA" sweep --seeds 1..4 -j 2 --out conf-$v --check "$root/examples/checks/confined -r /etc -r /usr /work/data" -- "$files" $v >conf-$v.txt 2>&1 || true
    done
    for v in bug fixed; do
        "$PATINA" sweep --seeds 1..4 -j 2 --out mark-$v --check "$root/examples/checks/synced-before-mark /work/data.log ack" -- "$marklog" $v >mark-$v.txt 2>&1 || true
    done
) &
sweeps=$!
for n in tour tour2; do is $n "$(run $n -- "$files" tour)" 0 ok exit; "$PATINA" inspect events $n >$n.jsonl; done
is app "$(run app --disk app:/var/lib/app -- "$files" tour)" 0 ok exit
cmp -s tour.jsonl tour2.jsonl || die "two runs of one seed: the streams differ"
jq -e -s '.[0].v == 1 and all(.[1:][]; (.type | type) == "string" and (.boot | type) == "number")' tour.jsonl >/dev/null || die "a line without type or inc"
ops=$(jq -r 'select(.type == "op" and .op != "close") | "\(.op) \(.path)\(if .to then " " + .to else "" end)"' tour.jsonl | paste -sd,)
[ "$ops" = "mkdir /work/a,mkdir /work/b,create /work/a/x,rename /work/a/x /work/b/y,write /work/b/y,fsync /work/b/y" ] || die "tour: ops: $ops"
traps=$("$PATINA" inspect dump tour/boot-1/boundary.log | awk '$2 == "trap"' | wc -l)
calls=$(jq -s 'map(select(.type | IN("call", "sdk", "mark"))) | length' tour.jsonl)
[ "$calls" = "$traps" ] || die "tour: $calls calls for $traps trap records"
rc=0
"$PATINA" verify --seed 2 --runs 5 --vary cpu,aslr --out lp -- "$PATINA_GUESTS/oracles-paths" tour >lp.txt 2>&1 || rc=$? # lint-allow: seed — verify repeats one seed; any seed shows it
[ "$rc" = 0 ] && grep -q '^identical: 5 runs' lp.txt || die "verify, paths: $(tail -3 lp.txt)"
lp=$("$PATINA" inspect events lp/run-0 --types call | jq -r 'select(.path == "link/a.txt") | .resolved')
[ "$lp" = /work/data/a.txt ] || die "paths: link/a.txt resolved to '$lp'"
app=$("$PATINA" inspect events app --types op | jq -r 'select(.type == "op") | .path' | sort -u | paste -sd,)
[ "$app" = "/var/lib/app/a,/var/lib/app/a/x,/var/lib/app/b,/var/lib/app/b/y" ] || die "--disk DIR:/var/lib/app: paths $app"
wait "$sweeps"
# found: GROUPS SIGNATURE-PREFIX (one group whose signature starts so), or none
found() {
    g=$(jq -r '[.groups[].signature] | join(" | ")' "$1/report.json")
    case $2 in
        none) [ -z "$g" ] && [ "$(jq .outcomes.ok "$1/report.json")" = 4 ] ;;
        *) case $g in "$2"*) [ "$(jq '.groups | length' "$1/report.json")" = 1 ] ;; *) false ;; esac ;;
    esac || die "$1: groups '$g', want $2: $(tail -3 "$1.txt")"
}
found conf-other "violation check: outside-roots: mkdir /work/other"
found conf-data none
found mark-bug "violation check: ack-before-fsync: ack N (seq N)"
found mark-fixed none

# 5. A serving checker, case settings, faults in known patterns, the report's size.
# chk/calc as a server (its file names PATINA_CHECK_SERVE): a line per run, its environment
# set from the line.
printf '%s\n' '#!/bin/sh' '# serves: PATINA_CHECK_SERVE' 'while read -r l; do' \
  '  eval "$(printf "%s" "$l" | jq -r ".env | to_entries[] | \"export \(.key)=\(.value | @sh)\"")"' \
  '  out=$("$(dirname "$0")/calc" "$(printf "%s" "$l" | jq -r .rundir)") && echo pass || echo "fail $out"' \
  'done' >chk/calc-serve
printf '#!/bin/sh\n# PATINA_CHECK_SERVE\nwhile read -r l; do echo maybe; done\n' >chk/serve-garbage
printf '#!/bin/sh\n# PATINA_CHECK_SERVE\nexit 0\n' >chk/serve-gone
chmod +x chk/calc-serve chk/serve-garbage chk/serve-gone
# calcs NAME FLAGS: the calc sweep with a checker given in FLAGS
calcs() { n=$1; shift; rc=0; "$PATINA" sweep --seeds 1..2 -j 4 --cases calc.txt --mount "$RUNS/calc:/calc" --out "$n" "$@" >"$n.txt" 2>&1 || rc=$?; echo "$rc"; }
rc=$(calcs calcs-serve --known known2 --check chk/calc-serve)
groups() { jq -c '[.groups[] | [.signature, (.cases | length), .count]]' "$1/report.json"; }
[ "$rc" = 0 ] || die "calc served: exit $rc"
lhs=$(groups calcs-serve); rhs=$(groups calcs)
[ "$lhs" = "$rhs" ] || die "calc served: groups $lhs, --check gave $rhs"
# A server that answers anything but a verdict, or ends, judges nothing: every run is an error.
for s in garbage gone; do
  rc=$(calcs calcs-$s --check chk/serve-$s)
  [ "$rc" = 2 ] && [ "$(jq '.check.errors' calcs-$s/report.json)" = 18 ] && [ "$(jq '.check.passed' calcs-$s/report.json)" = 0 ] || die "a server that $s: exit $rc: $(jq -c .check calcs-$s/report.json)"
done
# The health note: every judged run passed and no !ID entry shows the check can fail.
[ "$(jq '.check.unproven' conf-data/report.json)" = true ] && [ "$(jq '.check.unproven' calcs/report.json)" = false ] || die "check.unproven: conf-data $(jq .check.unproven conf-data/report.json), calcs $(jq .check.unproven calcs/report.json)"
# --ok-exit any: every exit status, never a signal.
is okany "$(run okany --ok-exit any -- /bin/sh -c 'exit 200')" 0 ok ok-exit
is okanysig "$(run okanysig --ok-exit any -- /usr/bin/python3 -I -c 'import os; os.abort()')" 1 crash signal
# Faults in a known pattern: fs-short fired in every upcase finding.
printf '%s\n' 'calm violation check: wrong-output* {faults: -}' 'short violation check: wrong-output* {faults: *fs-short*}' >known-f
[ "$("$PATINA" inspect summary --format json --known known-f up1 | jq -r '[.known.entries[] | "\(.id)=\(.count)"] | join(" ")')" = "calm=0 short=$(jq .findings up1/report.json)" ] || die "{faults: ...} in a known pattern"
# Case lines with settings: their own --env and --disk; [CASE] is the line after its settings.
mkdir cw && echo from-work >cw/f
printf '%s\n' "--env V=one -- /bin/sh -c 'echo \$V; cat /w/f; exit 1' a" "--disk $RUNS/cw:/w --env V=two -- /bin/sh -c 'echo \$V; cat /w/f; exit 1' b" >cw.txt
"$PATINA" sweep --seeds 1 --cases cw.txt --out cw-s >cw.out 2>&1 || true
[ "$(cat cw-s/seed-1/1-a/boot-1/stdout | head -1) $(cat cw-s/seed-1/2-b/boot-1/stdout | paste -sd' ')" = "one two from-work" ] || die "case settings: $(cat cw-s/seed-1/*/boot-1/stdout)"
[ "$(jq -r '[.groups[].runs[].case] | sort | join(",")' cw-s/report.json)" = "/bin/sh -c 'echo \$V; cat /w/f; exit 1' a,/bin/sh -c 'echo \$V; cat /w/f; exit 1' b" ] || die "the case of a line with settings: $(jq -c '[.groups[].runs[].case]' cw-s/report.json)"
echo '--fault fs-error-permille=1 -- /bin/true' >cw-bad.txt
rc=0
"$PATINA" sweep --seeds 1 --cases cw-bad.txt --out cw-bad >cw-bad.out 2>&1 || rc=$?
[ "$rc" = 2 ] && grep -q -- '--fault is a setting of the whole sweep' cw-bad.out && [ ! -e cw-bad/seed-1 ] || die "a sweep's flag on a case line: exit $rc: $(cat cw-bad.out)"
# The report: a group in full by its number, and its runs listed in report.json.
"$PATINA" inspect summary --group 2 calcs >g2.txt || true
lhs=$(head -1 g2.txt); rhs=$(jq -r '.groups[1].signature' calcs/report.json)
[ "$lhs" = "$rhs" ] && grep -q '^  replay: ' g2.txt || die "report --group 2: $(cat g2.txt)"
lhs=$(jq '[.groups[].runs | length] | add' calcs/report.json); rhs=$(jq .findings calcs/report.json)
[ "$lhs" = "$rhs" ] || die "report.json: groups do not list every finding's run"
echo "serve: $(groups calcs-serve); garbage and gone: 18 errors each; case settings, faults patterns, --group, --ok-exit any"
fi

# 6. Judging kept runs again (`patina recheck`). The same checker leaves every kept run's
#    result.json as it was, byte for byte; a checker that names its finding LABEL [KEY] is
#    grouped by the key alone in every run whose logs were kept, and the report shows one
#    finding as the checker wrote it.
for r in calcs/seed-*/*; do [ ! -d "$r/boot-1" ] || cp "$r/result.json" "$r/result.before"; done
"$PATINA" recheck calcs >rk.txt 2>&1 || true
n=0
for b in calcs/seed-*/*/result.before; do
    cmp -s "$b" "${b%.before}.json" || die "recheck with the same checker rewrote $(dirname "$b")/result.json"
    n=$((n + 1))
done
[ "$n" -gt 0 ] || die "no kept calc run to judge again"
sed 's/echo "wrong-$1: got $g, want $w"/echo "wrong [$1]: got $g, want $w (0x$g)"/' chk/calc >chk/calc-key && chmod +x chk/calc-key
"$PATINA" recheck --check chk/calc-key calcs >rk2.txt 2>&1 || true
# Every finding whose logs the sweep kept (a group's first three) is judged again; the others
# keep their verdict, as a pruned ok run does.
keyed=$(for r in calcs/seed-*/*; do [ ! -d "$r/boot-1" ] || jq -r 'select(.outcome == "violation") | .signature' "$r/result.json"; done | sort -u | paste -sd,)
[ "$keyed" = "violation check: wrong [mul],violation check: wrong [sub]" ] || die "keyed findings: $keyed"
ex=$(jq -r '[.groups[] | select(.signature | contains("["))][0].example' calcs/report.json)
case $ex in *0x[0-9]*) ;; *) die "the example is not as written: $ex" ;; esac
echo "recheck: $n kept runs unchanged by the same checker; keyed: $keyed, e.g. $ex"

wait "$hang" || true
is hang "$(cat hang.rc)" 2 error check
echo "ok: kvlog found, replayed and minimised; failing checkers are errors; the alternating one is check-unstable; the event stream names paths at the moment; confined and synced-before-mark find their bugs"
