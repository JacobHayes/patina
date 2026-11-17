# The examples (examples/README.md), each with its documented sweep options over seeds 1-20:
# the bug is found, under the expected signature; the fixed variant is ok on every seed, and
# the fault or fault point the example is about fired in at least one of those runs. stats-c's
# stock build is ok on every seed (its race needs compute points).
#@ tier=quick budget=20 slots=4 arch=x86_64
set -eu
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
E=$PATINA_GUESTS/examples
FAILS=0
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

# sweep OUT [options] -- CMD: seeds 1-20; prints patina's exit status
sweep() {
    out=$1; shift
    rc=0
    "$PATINA" sweep --seeds 1..20 -j 4 --keep none --out "$out" "$@" >"$out.txt" 2>&1 || rc=$?
    echo "$rc"
}

# example NAME SIGNATURE FAULTED [options] -- CMD: CMD finds SIGNATURE; CMD fixed is ok. FAULTED=1:
# the fixed runs must show an injected fault or a fault point that fired.
example() {
    name=$1 want=$2 faulted=$3; shift 3
    rc=$(sweep "$RUNS/$name" "$@")
    got=$(jq -r '[.groups[].signature] | join(" | ")' "$RUNS/$name/report.json")
    echo "$name: exit $rc, $(jq -r .findings "$RUNS/$name/report.json") findings: $got"
    [ "$rc" = 1 ] && [ "$got" = "$want" ] || fail "$name: expected exactly the finding '$want'"
    rc=$(sweep "$RUNS/$name-fixed" "$@" fixed)
    fired=$(cat "$RUNS/$name-fixed"/seed-*/result.json | jq -s '[.[] | select(.faults.injected > 0 or any(.sdk.sites[]; .kind == "buggify" and .held > 0))] | length')
    echo "$name fixed: exit $rc, $(jq -c .outcomes "$RUNS/$name-fixed/report.json"), $fired runs with a fault"
    [ "$rc" = 0 ] || fail "$name fixed: not ok on every seed"
    [ "$faulted" = 0 ] || [ "$fired" -gt 0 ] || fail "$name fixed: no fault fired, so the pass shows nothing"
}

example quickstart 'failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101' 0 \
    -- "$E/jobs"
example ledger 'violation always: ledger-sorted: after N' 1 --buggify -- "$E/ledger"
example journal-py 'violation always: journal-intact: N bytes' 1 --faults disk --mount "$E":/guest -- python3 /guest/journal.py
example acklog-c 'violation always: acked-records-kept: N acknowledged, N stored' 1 --crash machine -- "$E/acklog"
example bank-go 'violation always: balance-matches-deposits: balance N, deposits N' 1 --fault net-reset-permille=50 -- "$E/bank"
example serve-c 'violation always: served-only-public: N bytes' 1 --fault path-swap-permille=300 -- "$E/serve"
example stats-c 'failure exit: lost updates: N of N jobs counted; exit 1' 0 -- "$E/stats-cp"
# stats-c built without compute points: the race has no system call in it, so no seed finds it.
rc=$(sweep "$RUNS/stats-c-stock" -- "$E/stats")
echo "stats-c stock: exit $rc, $(jq -c .outcomes "$RUNS/stats-c-stock/report.json")"
[ "$rc" = 0 ] || fail "stats-c stock: a finding without compute points"

[ "$FAILS" = 0 ] || { echo "$FAILS check(s) failed"; exit 1; }
echo "all checks passed"
