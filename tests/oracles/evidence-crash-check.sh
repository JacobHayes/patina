# Evidence (a crash check on a program with no SDK): examples/kvlog-c with
# examples/checks/acked-kept, SEEDS (default 200) seeds under --crash machine, then every crash
# point of seeds 1 and 2 (--branch), then `kvlog fixed` under both. Prints each sweep's
# summary head (findings, the check: line); kvlog must have a finding and kvlog fixed none.
#@ tier=evidence budget=60 slots=8
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
n=${SEEDS:-200}
kv=$PATINA_GUESTS/examples/kvlog
sweep() {
    name=$1; shift
    st=0
    PATINA_TEST_KEEP_NONE=1 "$PATINA" sweep -j 8 --out "$RUNS/$name" --check "$root/examples/checks/acked-kept" "$@" >"$RUNS/$name.txt" 2>/dev/null || st=$?
    echo "== $name: exit $st"
    sed -n '/^patina sweep:/,/^$/p' "$RUNS/$name.txt" | grep -v '^$'
    grep -A1 '^violation' "$RUNS/$name.txt" || true
    echo "$st"  >"$RUNS/$name.rc"
}
sweep plain --seeds "1..$n" --crash machine -- "$kv"
sweep branch --seeds 1..2 --branch --crash machine -- "$kv"
sweep fixed --seeds "1..$n" --crash machine -- "$kv" fixed
sweep fixed-branch --seeds 1..2 --branch --crash machine -- "$kv" fixed
[ "$(cat "$RUNS/plain.rc")" = 1 ] && [ "$(cat "$RUNS/branch.rc")" = 1 ] || { echo "FAIL: kvlog: no finding"; exit 1; }
[ "$(cat "$RUNS/fixed.rc")" = 0 ] && [ "$(cat "$RUNS/fixed-branch.rc")" = 0 ] || { echo "FAIL: kvlog fixed: not clean"; exit 1; }
