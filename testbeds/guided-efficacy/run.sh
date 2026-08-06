#!/usr/bin/env bash
# Measure whether `campaign --guided` reaches a hard target in FEWER generations
# than uniform sampling. This is an efficacy gate, not a correctness gate: Wave E's
# determinism and tear-safety are proven by `campaign --selftest` and the e2e
# suite, whereas this answers the separate question of whether the selection
# policy earns its keep.
#
# Fixture: `staircase.rs` gates three nested stages on three campaign fault knobs
# that live in DIFFERENT bytes of the generation-derivation hash, so partial
# progress is inheritable by the mutation operator. Reaching a deeper stage covers
# a whole function's worth of new edges — the novelty signal `--guided` steers by.
#
# Campaign resumability keeps this cheap: the budget grows in blocks and an
# extended campaign reproduces a fresh one of the same length.
set -uo pipefail

usage() {
    cat <<'USAGE'
usage: run.sh [--block N] [--max N] [--seeds N] [--patina PATH] [--help]

  --block N    generations added per probe step (default 10)
  --max N      per-seed generation budget before giving up (default 100)
  --seeds N    number of seed bases per mode (default 6)
  --patina P   cargo-patina binary (default: cargo run -q -p cargo-patina --)

Exit codes: 0 = guided reached the target at least as fast as unguided on every
seed base; 1 = guided was SLOWER on at least one seed base (the policy is not
earning its keep); 2 = usage/setup error.
USAGE
}

BLOCK=10; MAX=100; SEEDS=6; PATINA=""
while [ $# -gt 0 ]; do
    case "$1" in
        --block) BLOCK="$2"; shift 2 ;;
        --max) MAX="$2"; shift 2 ;;
        --seeds) SEEDS="$2"; shift 2 ;;
        --patina) PATINA="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="${TMPDIR:-/tmp}/patina-guided-efficacy.$$"
mkdir -p "$work" || exit 2
trap 'rm -rf "$work"' EXIT

if [ -n "$PATINA" ]; then
    patina() { "$PATINA" patina "$@"; }
else
    patina() { (cd "$here/../.." && cargo run -q -p cargo-patina -- patina "$@"); }
fi

guest="$work/stair-native"
patina build "$here/staircase.rs" --output "$guest" --yield-points >/dev/null || {
    echo "guided-efficacy: FAILED to build the staircase guest" >&2; exit 2; }

# Non-vacuity: the target must be reachable at all, or every number below is
# meaningless. Drive the knobs to their ceiling and require stage three.
if ! patina run "$guest" --seed 1 --fs-error-permille 100 --fs-short-permille 200 \
        --sleep-jitter-nanos 0..2550000 2>&1 | grep -q STAGE_THREE; then
    echo "guided-efficacy: FAILED — the staircase is unreachable even at the knob ceiling" >&2
    exit 2
fi

covered() { # $1 = out-dir, $2 = function name
    patina coverage "$guest" "$1/coverage" --top 400 2>/dev/null \
        | awk -v f="$2" '$0 ~ f {split($3,a,"/"); sub("edges=","",a[1]); if (a[1]+0>0) {print 1; exit}}' \
        | head -1
}

measure() { # $1 = mode, $2 = seed base -> generations to stage three, or MAX+1
    local mode="$1" seed="$2" flag="" out="$work/$1-$2" done_gens=0
    [ "$mode" = guided ] && flag="--guided"
    rm -rf "$out"
    while [ "$done_gens" -lt "$MAX" ]; do
        if [ "$done_gens" -eq 0 ]; then
            patina campaign "$guest" --gens "$BLOCK" --faults --seed-start "$seed" \
                $flag --out-dir "$out" >/dev/null 2>&1
        else
            patina campaign --extend "$BLOCK" --out-dir "$out" >/dev/null 2>&1
        fi
        done_gens=$((done_gens + BLOCK))
        if [ "$(covered "$out" stage_three)" = 1 ]; then echo "$done_gens"; return; fi
    done
    echo $((MAX + 1))
}

echo "== guided efficacy (block=$BLOCK max=$MAX seeds=$SEEDS) =="
printf '%-10s %-10s %-10s %s\n' seed_base unguided guided verdict
slower=0
for seed in $(seq 0 $((SEEDS - 1))); do
    u="$(measure unguided "$seed")"
    g="$(measure guided "$seed")"
    if [ "$g" -lt "$u" ]; then verdict=faster
    elif [ "$g" -eq "$u" ]; then verdict=tie
    else verdict=SLOWER; slower=$((slower + 1))
    fi
    printf '%-10s %-10s %-10s %s\n' "$seed" "$u" "$g" "$verdict"
done

echo
if [ "$slower" -eq 0 ]; then
    echo "GUIDED_EFFICACY PASS slower_seeds=0"
    exit 0
fi
echo "GUIDED_EFFICACY FAIL slower_seeds=$slower — guidance cost generations rather than saving them"
exit 1
