#!/usr/bin/env bash
###############################################################################
# redb under Patina -- self-checking regression (rung 3).
#
# The SAME harness binary and SAME program args as run-native.sh, with only the
# runner swapped to `cargo patina run`. std::fs is routed through the
# deterministic, crash-injecting filesystem; the db lives at an absolute path in
# the writable in-memory guest filesystem (NO --mount: that mounts read-only).
#
# Exits nonzero on any regression:
#   1. clean `full` runs are green and deterministic across seeds (and distinct
#      across seeds -- non-vacuous);
#   2. a recorded run replays byte-identically;
#   3. a bounded crash sweep exposes NO durability violation (every commit redb
#      acknowledged survives every injected crash point).
###############################################################################
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
harness_dir="$repo_root/testbeds/redb-harness"
built_bin="$harness_dir/target/patina/redb-harness"
PATINA="$repo_root/target/release/cargo-patina"

cd "$repo_root"

echo "==> building cargo-patina and the harness under Patina"
cargo build --release --quiet -p cargo-patina
mkdir -p "$harness_dir/target/patina"
"$PATINA" patina build "$harness_dir" --output "$built_bin" --release >/dev/null

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

# The guest db path lives in the writable in-memory CrashFs (absolute, under a
# guest directory redb creates). The Patina --seed varies the deterministic
# world; the harness --seed fixes the workload.
DB=/db/redb.redb
run() { "$PATINA" patina run "$built_bin" "$@"; }
# `replay <trace> [flags]` reproduces a recorded run flag-free: the seed, fault
# knobs, and guest arguments are all restored from the trace metadata.
replay() { "$PATINA" patina replay "$built_bin" "$@"; }
result_of() { sed -n 's/^\(RESULT .*\)$/\1/p'; }

echo "==> [1] clean full mode: 5 seeds, each 3 repeats byte-identical, cross-seed distinct"
declare -a states=()
for seed in 1 2 3 4 5; do
  a="$(run --seed 1 -- --seed "$seed" --ops 300 --db "$DB" --mode full --threads 1 | result_of)"
  b="$(run --seed 1 -- --seed "$seed" --ops 300 --db "$DB" --mode full --threads 1 | result_of)"
  c="$(run --seed 1 -- --seed "$seed" --ops 300 --db "$DB" --mode full --threads 1 | result_of)"
  echo "    seed $seed: $a"
  if [[ "$a" != "$b" || "$a" != "$c" ]]; then
    echo "    MISMATCH: full mode not deterministic at seed $seed"; fail=1
  fi
  if [[ -z "$a" ]]; then echo "    MISSING RESULT at seed $seed"; fail=1; fi
  states+=("$(sed -n 's/.*state=\([0-9a-f]*\).*/\1/p' <<<"$a")")
done
distinct="$(printf '%s\n' "${states[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "$distinct" -ne "${#states[@]}" ]]; then
  echo "    VACUOUS: only $distinct distinct state hashes across ${#states[@]} seeds"; fail=1
fi

echo "==> [2] record + strict replay is byte-identical"
rec="$work/full.trace"
r1="$(run --record "$rec" -- --seed 3 --ops 300 --db "$DB" --mode full --threads 1 | result_of)"
r2="$(replay "$rec" | result_of)"
echo "    record: $r1"
echo "    replay: $r2"
if [[ "$r1" != "$r2" || -z "$r1" ]]; then
  echo "    MISMATCH: replay differs from record"; fail=1
fi

echo "==> [3] bounded crash sweep: no acknowledged commit is ever lost or torn"
# A representative subset of crash-sweep.sh; the full tabulation lives there.
declare -A tally=()
sweep_fail=0
for spec in write:2 write:8 write:20 write:48 write:90 write:160 \
            sync:1 sync:3 sync:8 sync:18 sync:36 \
            close:1 close:2 close:4; do
  for fseed in 0 1; do
    line="$(run --seed "$fseed" --fs-crash-at "$spec" -- \
      --seed 42 --ops 400 --db "$DB" --mode crash --threads 1 2>/dev/null || true)"
    outcome="$(sed -n 's/.*outcome=\([A-Z_]*\).*/\1/p' <<<"$line")"
    [[ -z "$outcome" ]] && outcome=NO_LINE
    tally["$outcome"]=$(( ${tally["$outcome"]:-0} + 1 ))
    if [[ "$outcome" == "LOST_COMMIT" || "$outcome" == "TORN_STATE" || "$outcome" == "NO_LINE" ]]; then
      echo "    !! $spec seed=$fseed -> $line"; sweep_fail=1
    fi
  done
done
echo -n "    outcomes:"
for o in NO_CRASH HOLDS OPEN_ERR OPEN_PANIC LOST_COMMIT TORN_STATE NO_LINE; do
  [[ "${tally[$o]:-0}" -gt 0 ]] && printf ' %s=%d' "$o" "${tally[$o]}"
done
echo
if [[ "$sweep_fail" -ne 0 ]]; then
  echo "    DURABILITY VIOLATION or missing line in the crash sweep"; fail=1
fi

echo "==> [4] fault run replays self-contained (flag-free) from the trace metadata"
# Record a sub-block (byte-granularity) crash run, then replay it with NO fault
# flags: the trace's recorded fault configuration is authoritative, so the
# injected crash and its torn image reproduce byte-identically without
# re-supplying --fs-crash-at/--fs-torn-granularity.
crash_rec="$work/crash.trace"
c1="$(run --seed 1 --fs-crash-at write:16 --fs-torn-granularity byte --record "$crash_rec" -- \
  --seed 42 --ops 400 --db "$DB" --mode crash --threads 1 2>/dev/null \
  | sed -n 's/^\(CRASH .*\)$/\1/p')"
c2="$(replay "$crash_rec" 2>/dev/null \
  | sed -n 's/^\(CRASH .*\)$/\1/p')"
echo "    record: $c1"
echo "    replay: $c2"
if [[ "$c1" != "$c2" || -z "$c1" ]]; then
  echo "    MISMATCH: flag-free replay of the fault run differs from record"; fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "==> FAILED"; exit 1
fi
echo "==> all Patina checks passed"
