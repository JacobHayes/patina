# The examples (examples/README.md), each with its documented sweep options: the bug is found,
# under the expected signature, by a search of seeds 1-20 that stops at the first finding
# (`--max-findings 1`; 1-200 in the release tier); the fixed variant is ok on every seed of 1-8
# (1-200 in the release tier), and the fault or fault point the example is about fired in at
# least one of those runs. stats-c searches seeds 1-10 and runs its fixed variant on 1-4 (1-10 in
# the release tier, as documented: half its seeds switch every 1 to 16 events in its rebuilt
# code, seconds a seed on the arm64 runner). stats-c's stock build is ok on every seed of 1-8
# (1-200 in the release tier) under traps (its race needs points in its code).
#@ tier=quick,release budget=20 budget-release=120 slots=2
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
E=$PATINA_GUESTS/examples
N=20 F=8
[ "${CHECK_TIER:-}" != release ] || N=200 F=200
FAILS=0
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

# sweep OUT SEEDS [options] -- CMD: seeds 1-SEEDS; prints patina's exit status
sweep() {
    out=$1 seeds=$2; shift 2
    rc=0
    PATINA_TEST_KEEP_NONE=1 "$PATINA" sweep --seeds "1..$seeds" -j 4 --out "$out" "$@" >"$out.txt" 2>&1 || rc=$?
    echo "$rc"
}

# example NAME SIGNATURE FAULTED [options] -- CMD: CMD finds SIGNATURE; CMD fixed is ok. FAULTED=1:
# the fixed runs must show an injected fault or a fault point that fired.
example() {
    name=$1 want=$2 faulted=$3; shift 3
    rc=$(sweep "$RUNS/$name" "$N" --max-findings 1 "$@")
    got=$(jq -r '[.groups[].signature] | join(" | ")' "$RUNS/$name/report.json")
    echo "$name: exit $rc, $(jq -r .findings "$RUNS/$name/report.json") findings: $got"
    [ "$rc" = 1 ] && [ "$got" = "$want" ] || fail "$name: expected exactly the finding '$want'"
    rc=$(sweep "$RUNS/$name-fixed" "$F" "$@" fixed)
    fired=$(cat "$RUNS/$name-fixed"/seed-*/result.json | jq -s '[.[] | select(.faults.injected > 0 or any(.sdk.sites[]; .kind == "buggify" and .held > 0))] | length')
    echo "$name fixed: exit $rc, $(jq -c .outcomes "$RUNS/$name-fixed/report.json"), $fired runs with a fault"
    [ "$rc" = 0 ] || fail "$name fixed: not ok on every seed"
    [ "$faulted" = 0 ] || [ "$fired" -gt 0 ] || fail "$name fixed: no fault fired, so the pass shows nothing"
}

example quickstart 'failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101' 0 \
    -- "$E/jobs"
example ledger 'violation always: ledger-sorted: after N' 1 --faults buggify -- "$E/ledger"
example journal-py 'violation always: journal-intact: N bytes' 1 --faults disk --mount "$E":/guest -- python3 /guest/journal.py
example acklog-c 'violation always: acked-records-kept: N acknowledged, N stored' 1 --faults crash -- "$E/acklog"
example bank-go 'violation always: balance-matches-deposits: balance N, deposits N' 1 --fault net-reset-permille=1000 -- "$E/bank"
example serve-c 'violation always: served-only-public: N bytes' 1 --fault path-swap-permille=300 -- "$E/serve"
# stats-c rebuilt with compute points: its race is found by the points it was rebuilt with.
all=$N fixed=$F
N=10 F=4
[ "${CHECK_TIER:-}" != release ] || F=10
example stats-c 'failure exit: lost updates: N of N jobs counted; exit 1' 0 -- "$E/stats-cp"
N=$all F=$fixed
# stats-c built without compute points, under [sched] preempt = "traps": the race has no system
# call in it, so no seed finds it without points in its code.
T=$("$PATINA_CFG" preempt=traps)
rc=$(sweep "$RUNS/stats-c-stock" "$F" --config "$T" -- "$E/stats")
echo "stats-c stock: exit $rc, $(jq -c .outcomes "$RUNS/stats-c-stock/report.json")"
[ "$rc" = 0 ] || fail "stats-c stock: a finding without compute points"

[ "$FAILS" = 0 ] || { echo "$FAILS check(s) failed"; exit 1; }
echo "all checks passed"
