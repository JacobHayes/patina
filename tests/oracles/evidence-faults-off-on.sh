# Evidence (a faults-off/on check finds a bug no assertion catches): examples/upcase-c, whose
# short write leaves the wrong file with exit 0, over SEEDS (default 200) seeds with --faults
# disk. Plainly: clean failures only. Against one faults-off reference run with --ok-exit 1
# and examples/checks/same-tree: one group, its first seed replayed identical, minimize keeping
# fs-short alone; `upcase fixed` ok on every seed.
#@ tier=evidence budget=60 slots=8
set -eu
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
n=${SEEDS:-200}
up=$PATINA_GUESTS/examples/upcase same=$root/examples/checks/same-tree
export PATINA
cd "$RUNS"
die() { echo "FAIL: $*"; exit 1; }
"$PATINA" run --seed 1 --out ref -- "$up" >ref.txt 2>&1 || die "reference: $(tail -2 ref.txt)"
sweep() { out=$1; shift; "$PATINA" sweep --seeds "1..$n" -j 8 --faults disk --out "$out" "$@" >"$out.txt" 2>&1 || true; }
sweep plain -- "$up"
sweep checked --ok-exit 1 --check "$same ref" -- "$up"
sweep fixed --ok-exit 1 --check "$same ref" -- "$up" fixed
for s in plain checked fixed; do
    jq -r --arg s "$s" '"\($s): \(.runs) runs, \(.findings) findings in \(.groups | length) groups, outcomes \(.outcomes | tostring), by --ok-exit \(.ok_exit // 0)"' "$s/report.json"
    jq -r '.groups[] | "  \(.count) \(.signature) | every: \(.faults.every | join(",")) | replay: \(.replay.result)"' "$s/report.json"
done
[ "$(jq -r '[.groups[].outcome] | unique | join(" ")' plain/report.json)" = failure ] || die "plain: not clean failures only"
[ "$(jq '.groups | length' checked/report.json)" = 1 ] || die "checked: not one group"
case $(jq -r '.groups[0].signature' checked/report.json) in "violation check: wrong-output"*) ;; *) die "checked: another signature" ;; esac
[ "$(jq -r '.groups[0].replay.result' checked/report.json)" = identical ] || die "checked: first seed's replay"
[ "$(jq '.findings' fixed/report.json)" = 0 ] && [ "$(jq '.outcomes.ok' fixed/report.json)" = "$n" ] || die "fixed: not ok on every seed"
first=$(jq -r '.groups[0].first.dir' checked/report.json)
"$PATINA" minimize "$first" --out min --format json >min.json 2>min.err || die "minimize: $(tail -2 min.err)"
echo "minimize: $(jq -r '"\(.from) -> \(.to)"' min.json)"
[ "$(jq -r .to min.json)" = "$(jq -r .to min.json | grep -o 'fs-short-permille=[^ ]*')" ] || die "minimize kept more than fs-short"
