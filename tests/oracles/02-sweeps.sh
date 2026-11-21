# The longer sweeps beside the quick tier's checks (01-checks.sh): `kvlog fixed` under machine
# crashes passes examples/checks/acked-kept on every seed; a sweep run again resumes (a kept
# run stays), and with the checker's file changed judges every run again (a kept run from its
# logs, a pruned one run again); upcase swept with disk faults
# and no checker has clean failures only, and `upcase fixed` under `--ok-exit 1 --check
# same-tree` has no finding.
#@ tier=area budget=20 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
kv=$PATINA_GUESTS/examples/kvlog up=$PATINA_GUESTS/examples/upcase
die() { echo "FAIL: $*"; exit 1; }
cd "$RUNS"
cp "$root/examples/checks/acked-kept" acked
export PATINA

rc=0
"$PATINA" sweep --seeds 1..30 -j 4 --crash machine:10 --out kvf --check ./acked -- "$kv" fixed >kvf.txt 2>&1 || rc=$?
[ "$rc" = 0 ] && [ "$(jq '.groups | length' kvf/report.json)" = 0 ] || die "kvlog fixed: exit $rc: $(tail -3 kvf.txt)"
[ "$(jq '.outcomes.ok' kvf/report.json)" = 30 ] || die "kvlog fixed: not 30 ok runs"

# The same sweep resumes (a kept run stays); with the checker's file changed, the runs are
# judged again by it: a kept run from its logs (it stays), a pruned one by running it again.
rc=0
"$PATINA" sweep --seeds 1..64 -j 4 --crash machine:10 --out kv --check ./acked -- "$kv" >kv.txt 2>&1 || rc=$?
first=$(jq -r '.groups[0].first.dir // empty' kv/report.json)
[ "$rc" = 1 ] && [ -n "$first" ] || die "kvlog sweep: exit $rc: $(tail -3 kv.txt)"
: >"$first/kept"
"$PATINA" sweep --seeds 1..64 -j 4 --crash machine:10 --out kv --check ./acked -- "$kv" >kv2.txt 2>&1 || true
[ -f "$first/kept" ] || die "the same sweep did not resume"
echo "# changed" >>acked
"$PATINA" sweep --seeds 1..64 -j 4 --crash machine:10 --out kv --check ./acked -- "$kv" >kv3.txt 2>&1 || true
[ -f "$first/kept" ] || die "a changed checker ran again a run it could judge again from its logs"
sha=$(sha256sum acked | cut -d' ' -f1)
old=$(jq -r --arg sha "$sha" 'select(.config.check.sha256 != $sha) | input_filename' kv/seed-*/run.json)
[ -z "$old" ] || die "runs still judged by the earlier checker: $old"

# upcase: plainly, clean failures only (fs errors at 20 per mille beside the disk preset: about
# two seeds in five fail, where the preset alone fails about one in twenty); fixed, against a
# faults-off reference, no finding.
"$PATINA" run --seed 1 --out upref -- "$up" >upref.txt 2>&1 || die "upcase reference: $(tail -2 upref.txt)" # lint-allow: seed — faults off, upcase writes the same tree on every seed
rc=0
"$PATINA" sweep --seeds 1..80 -j 4 --faults disk --fault fs-error-permille=20 --out up0 -- "$up" >up0.txt 2>&1 || rc=$?
[ "$rc" = 1 ] && [ "$(jq -r '[.groups[].outcome] | unique | join(" ")' up0/report.json)" = failure ] || die "upcase plain sweep: exit $rc: $(tail -3 up0.txt)"
rc=0
"$PATINA" sweep --seeds 1..40 -j 4 --faults disk --ok-exit 1 --check "$root/examples/checks/same-tree upref" --out up2 -- "$up" fixed >up2.txt 2>&1 || rc=$?
[ "$rc" = 0 ] && [ "$(jq '.groups | length' up2/report.json)" = 0 ] || die "upcase fixed: exit $rc: $(tail -3 up2.txt)"
echo "ok: kvlog fixed passes 30 seeds; a sweep resumes and a changed checker judges its runs again; upcase plainly $(jq -r .findings up0/report.json) clean failures, fixed none"
