# Evidence (triage of a corpus against a reference, docs/EVIDENCE.md "Oracles", third round):
# 200 generated cases `OP A B` of a calculator with two planted bugs (a difference above 50 is
# one too many; anything times 0 is the other operand) and one difference by design (it
# divides toward zero, the reference toward minus infinity), each case run at seeds 1-2.
# - Groups by a checker that writes `wrong-output: got G, want W`, then by one that keys its
#   finding by the operation, `wrong-output [OP]: ...` (patina recheck, and a fresh sweep).
# - The table of expected differences gains the division cases: patina recheck against the
#   same sweep run afresh (wall time, groups); the disk --keep checked, fail and all take.
# - The reference guard: the reference made with another work tree; then --relax work.
# - The fjall harness under --buggify (seed 1, seeds 1-4): exit status and the sdk lines, by
#   this build and, when OLD_PATINA names one, by an earlier build.
#@ tier=evidence budget=600 slots=8
: "${PATINA:?}" "${RUNS:?}" "${PATINA_WORKLOADS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$RUNS"
die() { echo "FAIL: $*"; exit 1; }
mkdir c chk t1 t2
echo one >t1/f
echo two >t2/f
cat >c/calc <<'EOF'
[ $# = 1 ] && set -- $1
case $1 in
add) echo $(($2 + $3)) ;;
sub) r=$(($2 - $3)); [ "$r" -gt 50 ] && r=$((r + 1)); echo "$r" ;;
mul) if [ "$3" = 0 ]; then echo "$2"; else echo $(($2 * $3)); fi ;;
div) echo $(($2 / $3)) ;;
esac
EOF
cat >c/ref <<'EOF'
[ $# = 1 ] && set -- $1
case $1 in
add) echo $(($2 + $3)) ;;
sub) echo $(($2 - $3)) ;;
mul) echo $(($2 * $3)) ;;
div) q=$(($2 / $3)) r=$(($2 % $3)); [ "$r" != 0 ] && [ $(((r < 0) != ($3 < 0))) = 1 ] && q=$((q - 1)); echo "$q" ;;
esac
EOF
awk 'BEGIN { split("add sub mul div", op, " ");
    for (i = 1; i <= 200; i++) { b = (i * 11) % 13 - 3; if (op[i % 4 + 1] == "div" && b == 0) b = 7;
        printf "%s %d %d\n", op[i % 4 + 1], (i * 37) % 120 - 20, b } }' >cases.txt
# The checkers: stdout as the reference's unless the table names the case; `keyed` keys a
# difference by the operation.
for k in plain keyed; do
    if [ $k = keyed ]; then key=' [$op]'; else key=; fi
    cat >chk/$k <<EOF
#!/bin/sh
grep -qx "\$PATINA_CASE_ID" "\$(dirname "\$0")/expected.txt" 2>/dev/null &&
    { echo "expected: case \$PATINA_CASE_ID differs by design"; exit 77; }
g=\$(cat "\$2/inc-0/stdout") w=\$(cat "\$1/seed-1/\$PATINA_CASE_NAME/inc-0/stdout")
[ "\$g" = "\$w" ] && exit 0
op=\${PATINA_CASE%% *}
echo "wrong-output$key: got \$g, want \$w"
exit 1
EOF
    chmod +x chk/$k
done
M="--mount $RUNS/c:/c"
# sweep NAME FLAGS...: a sweep into NAME, its text in NAME.txt; prints exit status and seconds.
sweep() {
    n=$1; shift
    t0=$(date +%s%N); rc=0
    # shellcheck disable=SC2086 # $M is two words
    "$PATINA" sweep -j 8 --cases cases.txt $M --out "$n" "$@" >"$n.txt" 2>&1 || rc=$?
    [ -f "$n/report.json" ] || die "$n: no report: $(tail -3 "$n.txt")"
    echo "$rc $(( ($(date +%s%N) - t0) / 1000000 ))"
}
# groups NAME: the groups of NAME/report.json, "count signature" each
groups() { jq -r '.groups[] | "  \(.count) \(.signature)   e.g. \(.example // "-")"' "$1/report.json"; }
secs() { echo "$1" | awk '{ printf "%.2f s", $2 / 1000 }'; }

set -- $(sweep ref --seeds 1 --keep all -- /bin/sh /c/ref {})
[ "$1" = 0 ] || die "the reference: exit $1"
echo "reference: 200 runs, $(secs "$*")"

# Groups before and after a key.
set -- $(sweep plain --seeds 1..2 --keep checked --check "chk/plain ref" -- /bin/sh /c/calc {})
echo "plain checker: exit $1, $(secs "$*"), $(jq '.groups | length' plain/report.json) groups"
groups plain
cp -R plain keyed-rk
t0=$(date +%s%N)
rc=0; "$PATINA" recheck --check "chk/keyed ref" keyed-rk >keyed-rk.txt 2>&1 || rc=$?
echo "keyed checker by recheck: exit $rc, $(( ($(date +%s%N) - t0) / 1000000 )) ms, $(jq '.groups | length' keyed-rk/report.json) groups"
groups keyed-rk
set -- $(sweep keyed --seeds 1..2 --keep checked --check "chk/keyed ref" -- /bin/sh /c/calc {})
echo "keyed checker by a fresh sweep: exit $1, $(secs "$*"), $(jq '.groups | length' keyed/report.json) groups"
sig() { jq -c '[.groups[] | [.signature, .count]] | sort' "$1/report.json"; }
a=$(sig keyed-rk) b=$(sig keyed)
[ "$a" = "$b" ] || die "recheck and a fresh sweep group differently: $a / $b"

# The table: the division cases the key named.
jq -r '.groups[] | select(.signature | test("\\[div\\]")) | .runs[].case_id' keyed/report.json | sort -un >chk/expected.txt
echo "table: $(wc -l <chk/expected.txt) division cases"
t0=$(date +%s%N)
rc=0; "$PATINA" recheck keyed >keyed-table.txt 2>&1 || rc=$?
rk=$(( ($(date +%s%N) - t0) / 1000000 ))
echo "recheck after the table edit: exit $rc, $rk ms: $(grep '^check: judged' keyed-table.txt)"
groups keyed
set -- $(sweep again --seeds 1..2 --keep checked --check "chk/keyed ref" -- /bin/sh /c/calc {})
echo "the same sweep afresh: exit $1, $(secs "$*"): $(grep '^check: judged' again.txt)"
a=$(sig keyed) b=$(sig again)
[ "$a" = "$b" ] || die "recheck and the fresh sweep differ: $a / $b"
set -- $(sweep fail --seeds 1..2 --check "chk/keyed ref" -- /bin/sh /c/calc {})
set -- $(sweep all --seeds 1..2 --keep all --check "chk/keyed ref" -- /bin/sh /c/calc {})
echo "disk (du -sk): --keep checked $(du -sk again | cut -f1) KiB, fail $(du -sk fail | cut -f1) KiB, all $(du -sk all | cut -f1) KiB"
rc=0; "$PATINA" recheck --check "chk/plain ref" fail >fail-rk.txt 2>fail-rk.err || rc=$?
echo "recheck of the --keep fail sweep: exit $rc: $(tail -1 fail-rk.err)"
awk '/^check: these/' fail-rk.txt

# The guard: the reference made with another work tree.
set -- $(sweep ref-t2 --seeds 1 --keep all --work t2 -- /bin/sh /c/ref {})
set -- $(sweep guard --seeds 1 --work t1 --check "$root/examples/checks/same-output ref-t2" -- /bin/sh /c/calc {})
echo "guard: exit $1: $(grep '^check: judged' guard.txt)"
echo "  $(jq -r '[.groups[] | select(.outcome == "error")][0].example' guard/report.json | sed "s|$RUNS|RUNS|g")"
set -- $(sweep relax --seeds 1 --work t1 --check "$root/examples/checks/same-output --relax work ref-t2" -- /bin/sh /c/calc {})
echo "--relax work: exit $1: $(grep '^check: judged' relax.txt)"

# The fjall harness under --buggify: the unmet-sites rule.
for b in new old; do
    if [ $b = old ]; then P=${OLD_PATINA:-}; else P=$PATINA; fi
    [ -n "$P" ] || continue
    for s in 1 1..4; do
        rc=0
        "$P" sweep -j 8 --seeds $s --buggify --keep none --out "fj-$b-$s" --mount "$PATINA_WORKLOADS/fjall-harness:/guest:copy" -- /guest/fjall-harness-release >"fj-$b-$s.txt" 2>&1 || rc=$?
        echo "fjall --buggify --seeds $s, $b build: exit $rc"
        awk '/^sdk/ { print "  " $0 }' "fj-$b-$s.txt"
    done
done
