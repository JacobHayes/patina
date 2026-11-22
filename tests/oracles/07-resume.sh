# A resumed sweep whose checker changed counts each run it judges again as a run it finished:
# the checker's new findings count toward --max-findings (reached, the sweep starts no run), and
# a run it now passes counts as an ok run and keeps its logs under --keep fail, as one the
# checker ran on would (for the checker to read again).
#@ tier=area budget=10 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
up=$PATINA_GUESTS/examples/upcase
die() { echo "FAIL: $*"; exit 1; }
rm -rf "${RUNS:?}/resume"
mkdir -p "$RUNS/resume" && cd "$RUNS/resume" || exit 1
verdict() { printf '#!/bin/sh\n# %s\n%s\n' "$1" "$2" >ck; chmod +x ck; }
sweep() { "$PATINA" sweep -j 4 --check ./ck --out sw "$@" -- "$up"; }

# Every run passes, every log kept.
verdict pass 'exit 0'
rc=0
sweep --seeds 1..6 --keep all >s1.txt 2>&1 || rc=$?
[ "$rc" = 0 ] || die "first sweep: exit $rc: $(tail -3 s1.txt)"
logs() { find sw -mindepth 2 -maxdepth 2 -name 'boot-*' | wc -l; }
[ "$(logs)" -gt 0 ] || die "--keep all kept no logs"

# The checker now rejects every run: the six judged again are findings, one group, which is
# --max-findings 1, so none of the six new seeds runs.
verdict reject 'echo rejected; exit 1'
rc=0
sweep --seeds 1..12 --max-findings 1 >s2.txt 2>&1 || rc=$?
[ "$rc" = 1 ] || die "rejecting checker: exit $rc: $(tail -3 s2.txt)"
ran=$(find sw -mindepth 2 -maxdepth 2 -name result.json | wc -l)
[ "$ran" = 6 ] || die "--max-findings reached by the runs judged again, yet $((ran - 6)) new runs ran: $(tail -3 s2.txt)"

# The checker passes them again: six ok runs, none run anew, each kept whole for the checker.
verdict pass-again 'exit 0'
rc=0
sweep --seeds 1..6 --keep fail >s3.txt 2>&1 || rc=$?
[ "$rc" = 0 ] || die "passing checker: exit $rc: $(tail -3 s3.txt)"
[ "$(jq -c '[.runs, .findings, .outcomes.ok]' sw/report.json)" = "[6,0,6]" ] || die "runs judged again and passed: $(jq -c '{runs, findings, outcomes}' sw/report.json)"
[ "$(find sw -mindepth 2 -maxdepth 2 -name result.json | wc -l)" = 6 ] || die "a run was started anew: $(tail -3 s3.txt)"
kept=$(logs)
[ "$kept" = 6 ] || die "$kept of 6 logs of runs judged again kept under --keep fail with a checker"
echo "ok: runs judged again count toward --max-findings and as finished runs, kept as the checker's"
