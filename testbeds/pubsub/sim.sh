#!/bin/sh
# Build pubsub and sweep it under Patina. Fails if the clean program has a finding or saw
# no fault, or if a planted bug is not found in the seed range.
#   SEEDS=N (200)  JOBS=N (8)  OUT=DIR (/tmp/pubsub-sim)  PATINA=path (patina on PATH)
set -eu
cd "$(dirname "$0")"
PATINA=${PATINA:-patina}
SEEDS=${SEEDS:-200}
JOBS=${JOBS:-8}
OUT=${OUT:-${TMPDIR:-/tmp}/pubsub-sim}
cargo build --release --quiet
bin=$(cd "${CARGO_TARGET_DIR:-target}/release" && pwd)/pubsub
mkdir -p "$OUT"
fail=0

# leg NAME EXPECT [patina options] -- [pubsub options]
# EXPECT is `clean`, or a string the finding's signature must contain.
leg() {
    name=$1 expect=$2
    shift 2
    dir=$OUT/$name
    rm -rf "$dir"
    "$PATINA" sweep --seeds "1..$SEEDS" -j "$JOBS" --keep fail --out "$dir" "$@" >"$dir.log" 2>&1 || true
    if [ ! -f "$dir/report.json" ]; then
        echo "FAIL $name: no report, see $dir.log"; fail=1; return
    fi
    if [ "$expect" = clean ]; then
        faulted=$(cat "$dir"/seed-*/result.json | jq -s '[.[] | .faults
            | select(.injected + ([.counts[]?.injected] | add // 0) > 0)] | length')
        if jq -e '.findings == 0 and .outcomes.ok == .runs and (.vacuous | not)' \
            "$dir/report.json" >/dev/null && [ "$faulted" -gt 0 ]; then
            echo "ok   $name: no finding in $SEEDS seeds, faults in $faulted"
        else
            echo "FAIL $name: findings, vacuous, or no fault ($faulted runs faulted), see $dir.log"
            fail=1
        fi
    else
        found=$(jq --arg s "$expect" \
            '[.groups[] | select(.signature | contains($s)) | .count] | add // 0' "$dir/report.json")
        if [ "$found" -gt 0 ]; then
            echo "ok   $name: found in $found of $SEEDS seeds"
        else
            echo "FAIL $name: not found ($expect), see $dir.log"; fail=1
        fi
    fi
}

net="--fault net-delay-ms=0..40 --fault net-chunk-max=16..4096 --fault net-halfclose-delay-ms=0..20"
# shellcheck disable=SC2086
leg clean clean $net -- "$bin"
leg lost-wakeup "failure exit: exit 1" -- "$bin" --bug lost-wakeup --timeout-secs 10
leg drop-read-remainder "always: seq-gap" -- "$bin" --bug drop-read-remainder
leg stale-timeout "always: liveness-timeout" -- "$bin" --bug stale-timeout
exit $fail
