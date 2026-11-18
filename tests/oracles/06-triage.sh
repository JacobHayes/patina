# 6. Triage with a checker that consults a table, against a reference implementation (bash
#    against dash, the cases a {} corpus):
#    - Case ids: a line's --name or its line number, in PATINA_CASE_ID, run.json, report.json
#      and the run's directory; --only-case runs one case; the report's rerun line runs.
#    - Keyed findings (LABEL [KEY]: detail) group by the key; reasons not to judge count by
#      their class (CLASS: detail).
#    - `patina recheck` after an edit of the checker's table judges the kept runs again: the
#      verdicts follow the table, and the runs' digests, logs and own outcomes are untouched;
#      the same checker again rewrites nothing. A run --keep fail pruned is not judged again:
#      the report names two checkers.
#    - A sweep resumed with its checker's file changed judges every run again from its logs
#      (--keep checked: none runs again), and a verdict left pending is judged again.
#    - --check-serve judges a recheck as --check does.
#    - same-output refuses a reference made from another work tree (an error, not a finding);
#      --relax compares anyway.
#@ tier=area budget=30 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
die() { echo "FAIL: $*"; exit 1; }
cd "$RUNS"
export PATINA
mkdir chk t1 t2
echo one >t1/f
echo two >t2/f
# The corpus: a comment, a named case with a work tree of its own, and a case dash and bash
# disagree on (dash's echo prints -e).
cat >cases.txt <<'EOF'
# ids: a line's --name, or its line number
--work t1 --name readf -- cat f
echo plain
echo -e 'a\tb'
printf '%s\n' 1 2
EOF
sed 's/^--work t1/--work t2/' cases.txt >cases-t2.txt
# The checker: stdout as the reference's, unless the table of expected differences names the
# case; a difference is keyed by the case's id.
cat >chk/diff <<'EOF'
#!/bin/sh
ref=$1/seed-1/$PATINA_CASE_NAME
if grep -qx "$PATINA_CASE_ID" "$(dirname "$0")/expected.txt" 2>/dev/null; then
    echo "expected: case $PATINA_CASE_ID differs by design"
    exit 77
fi
cmp -s "$ref/inc-0/stdout" "$2/inc-0/stdout" && exit 0
echo "wrong-output [$PATINA_CASE_ID]: got $(head -c 20 "$2/inc-0/stdout" | tr -c '[:print:]' .)"
exit 1
EOF
chmod +x chk/diff
# sweep NAME FLAGS...: a sweep of bash over the corpus into NAME; prints its exit status
sweep() { n=$1; shift; rc=0; "$PATINA" sweep --seeds 1..2 -j 4 --out "$n" "$@" >"$n.txt" 2>&1 || rc=$?; echo "$rc"; }
rc=0
"$PATINA" sweep --seeds 1 --keep all --cases cases.txt --out ref -- /bin/sh -c {} >ref.txt 2>&1 || rc=$?
[ "$rc" = 0 ] || die "the reference sweep: exit $rc: $(tail -3 ref.txt)"

# Ids, keys and classes.
rc=$(sweep sh --keep checked --cases cases.txt --check "chk/diff ref" -- /bin/bash -c {})
[ "$rc" = 1 ] || die "the subject sweep: exit $rc: $(tail -3 sh.txt)"
[ "$(jq -r '[.groups[].signature] | join(",")' sh/report.json)" = "violation check: wrong-output [4]" ] ||
    die "keyed groups: $(jq -c '[.groups[].signature]' sh/report.json)"
ids=$(jq -r '"\(.config.case.id) \(input_filename | split("/")[-2])"' sh/seed-1/*/run.json | sort | paste -sd,)
[ "$ids" = "3 3-plain,4 4-a_tb,5 5-2,readf 2-readf" ] || die "case ids and directories: $ids"
[ "$(jq -r '[.groups[].runs[].case_id] | unique | join(",")' sh/report.json)" = 4 ] || die "report.json case_id: $(jq -c '[.groups[].runs[].case_id]' sh/report.json)"
rerun=$(jq -r '.groups[0].rerun' sh/report.json)
rc=0
eval "\"\$PATINA\" run --out rerun --format json ${rerun#patina run }" >rerun.json 2>/dev/null || rc=$?
[ "$rc $(jq -r .signature rerun.json)" = "1 violation check: wrong-output [4]" ] || die "the rerun line ($rerun): exit $rc"
rc=$(sweep only --cases cases.txt --only-case readf --check "chk/diff ref" -- /bin/bash -c {})
[ "$rc" = 0 ] && [ "$(cd only && ls -d seed-*/* | paste -sd,)" = "seed-1/2-readf,seed-2/2-readf" ] || die "--only-case readf: exit $rc: $(cd only && ls -d seed-*/*)"
echo "ids: $ids; group $(jq -r '.groups[0].signature' sh/report.json), e.g. $(jq -r '.groups[0].example' sh/report.json)"

# The table names the case: a recheck judges every kept run again, and only the check changes.
mkdir own
# own RUN: what a recheck must not change: the digest, the program's end, faults, SDK, the log
own() { jq -c '{digest, guest, faults, sdk}' "$1/result.json"; sha256sum "$1/inc-0/boundary.log" | cut -d' ' -f1; }
for r in sh/seed-*/*; do own "$r" >"own/$(echo "$r" | tr / _)"; done
[ -f sh/seed-1/4-a_tb/replay.json ] || die "the finding's first seed was not replayed"
echo 4 >chk/expected.txt
rc=0
"$PATINA" recheck sh >rk.txt 2>rk.err || rc=$?
[ "$rc" = 0 ] && [ "$(jq '.groups | length' sh/report.json)" = 0 ] || die "recheck after the table edit: exit $rc: $(cat rk.txt rk.err)"
[ "$(jq -c '.check.not_judged' sh/report.json)" = '{"expected":2}' ] || die "not judged by class: $(jq -c .check sh/report.json)"
# The checker's file is unchanged but its verdict is not: the replay of the old one goes.
[ ! -e sh/seed-1/4-a_tb/replay.json ] || die "a replay of the earlier verdict was kept"
for r in sh/seed-*/*; do
    now=$(own "$r") was=$(cat "own/$(echo "$r" | tr / _)")
    [ "$now" = "$was" ] || die "recheck changed more than the check of $r"
    cp "$r/result.json" "own/$(echo "$r" | tr / _).result"
done
"$PATINA" recheck sh >/dev/null 2>&1 || die "recheck again: exit $?"
for r in sh/seed-*/*; do
    cmp -s "own/$(echo "$r" | tr / _).result" "$r/result.json" || die "the same checker again rewrote $r/result.json"
done
echo "recheck: the table's entry turns 2 findings into $(jq -c .check.not_judged sh/report.json); digests, logs and own outcomes unchanged"

# --check-serve judges as --check does.
"$PATINA" recheck --check "$root/examples/checks/same-output ref" sh >/dev/null 2>&1 || true
verdicts() { for r in sh/seed-*/*; do jq -r '"\(.check.verdict) \(.check.label)"' "$r/result.json"; done | paste -sd,; }
by_run=$(verdicts)
"$PATINA" recheck --check-serve "$root/examples/checks/same-output.py ref" sh >/dev/null 2>&1 || true
[ "$(verdicts)" = "$by_run" ] || die "--check-serve recheck: $(verdicts); --check: $by_run"

# Pruned runs: a recheck names them and leaves them; the report says two checkers judged.
mv chk/expected.txt chk/expected.off
rc=$(sweep shf --cases cases.txt --check "chk/diff ref" -- /bin/bash -c {})
mv chk/expected.off chk/expected.txt
[ "$rc" = 1 ] || die "the --keep fail sweep: exit $rc: $(tail -3 shf.txt)"
rc=0
"$PATINA" recheck --check "$root/examples/checks/same-output ref" --format json shf >shf.json 2>shf.err || rc=$?
[ "$rc" = 1 ] && [ "$(jq '.check.checkers | length' shf.json)" = 2 ] || die "recheck of pruned runs: exit $rc: $(jq -c .check shf.json) $(cat shf.err)"
[ "$(jq -r 'select(.config.check.program | endswith("chk/diff")) | input_filename' shf/seed-*/*/run.json | wc -l)" -gt 0 ] ||
    die "a pruned run was judged again"
# A failure whose logs --keep none pruned keeps the signature its stderr gave it.
echo 'echo boom-17 >&2; exit 3' >fails.txt
rc=$(sweep none --keep none --cases fails.txt --check "chk/diff ref" -- /bin/bash -c {})
before=$(jq -r .signature none/seed-1/1-3/result.json)
"$PATINA" recheck none >/dev/null 2>&1 || true
[ "$rc" = 1 ] && [ "$(jq -r .signature none/seed-1/1-3/result.json)" = "$before" ] ||
    die "a pruned failure's signature: exit $rc, $before, now $(jq -r .signature none/seed-1/1-3/result.json)"

# Resuming with the checker's file changed: judged again from the kept logs, none run again;
# and a verdict left pending is judged.
for r in sh/seed-*/*; do : >"$r/kept"; done
"$PATINA" recheck --check "chk/diff ref" sh >/dev/null 2>&1 || true
echo '# changed' >>chk/diff
rc=$(sweep sh --keep checked --cases cases.txt --check "chk/diff ref" -- /bin/bash -c {})
[ "$rc" = 0 ] || die "the resumed sweep: exit $rc: $(tail -3 sh.txt)"
sha=$(sha256sum chk/diff | cut -d' ' -f1)
for r in sh/seed-*/*; do
    [ -f "$r/kept" ] || die "$r ran again"
    [ "$(jq -r .config.check.sha256 "$r/run.json")" = "$sha" ] || die "$r: still the earlier checker's verdict"
done
# The same checker again: only the run whose verdict was left pending is judged.
p=sh/seed-2/5-2
jq '.check = {"verdict": "pending"} | .outcome = "error"' "$p/result.json" >p.json && mv p.json "$p/result.json"
rc=$(sweep sh --keep checked --cases cases.txt --check "chk/diff ref" -- /bin/bash -c {})
[ "$rc" = 0 ] && [ "$(jq -r .check.verdict "$p/result.json")" = pass ] || die "the pending verdict: exit $rc: $(jq -c .check "$p/result.json")"

# The reference guard: another work tree for readf is an error with its reason; --relax judges.
"$PATINA" sweep --seeds 1 --keep all --cases cases-t2.txt --out ref-t2 -- /bin/sh -c {} >ref-t2.txt 2>&1 || die "ref-t2: $(tail -2 ref-t2.txt)"
rc=$(sweep guard --cases cases.txt --check "$root/examples/checks/same-output ref-t2" -- /bin/bash -c {})
[ "$rc" = 1 ] && [ "$(jq -r '[.groups[] | select(.outcome == "error") | .cases[]] | join(",")' guard/report.json)" = "cat f" ] ||
    die "the guard: exit $rc: $(jq -c '[.groups[] | [.signature, .cases]]' guard/report.json)"
jq -e '.groups[] | select(.outcome == "error") | .example | test("reference-mismatch: work")' guard/report.json >/dev/null || die "the guard's reason: $(jq -c '[.groups[].example]' guard/report.json)"
rc=$(sweep relax --cases cases.txt --check "$root/examples/checks/same-output --relax work --relax settings ref-t2" -- /bin/bash -c {})
[ "$rc" = 1 ] && [ "$(jq '.check.errors' relax/report.json)" = 0 ] || die "--relax: exit $rc: $(jq -c .check relax/report.json)"
echo "guard: $(jq -r '.groups[] | select(.outcome == "error") | .example' guard/report.json)"
echo "ok: case ids, keys, classes; recheck after a table edit; serve as run; pruned runs named; a resume judges again; the reference guard"
