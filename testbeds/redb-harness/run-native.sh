#!/usr/bin/env bash
# Native (non-Patina) determinism + oracle smoke test for the redb harness.
#
# Native runs use the real filesystem and real threads, so there are no injected
# crashes here: what must hold is that the harness is DETERMINISTIC (same seed ->
# identical RESULT line) and SELF-CONSISTENT (its internal model matches the
# database, write == verify, integrity check passes). The Patina phase later
# reuses this exact binary and args to add crash/fsync fault injection.
#
# The run command is defined ONCE as $RUNNER. The Patina swap is a single-line
# change: point RUNNER at `cargo patina run ...` (see run-patina.sh) and every
# invocation below flows through it with identical program args.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# --- The one knob the Patina phase flips. Everything routes through $RUNNER. ---
RUNNER=(cargo run --release --quiet --)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> building release binary"
cargo build --release --quiet

# Extract just the RESULT line (the machine-parseable contract) from a run.
result_line() {
  "${RUNNER[@]}" "$@" | sed -n 's/^\(RESULT .*\)$/\1/p'
}

fail=0

# 1. full mode twice at the same seed into FRESH db paths -> identical RESULT.
echo "==> [1] full mode is deterministic across fresh databases"
a="$(result_line --seed 42 --ops 400 --db "$work/full-a.redb" --mode full)"
b="$(result_line --seed 42 --ops 400 --db "$work/full-b.redb" --mode full)"
echo "    a: $a"
echo "    b: $b"
if [[ "$a" != "$b" ]]; then
  echo "    MISMATCH: full mode not deterministic"
  fail=1
fi

# 2. write, then a SEPARATE cold verify of the same db -> matching RESULT lines.
echo "==> [2] cold verify reproduces the write RESULT line"
w="$(result_line --seed 7 --ops 400 --db "$work/wv.redb" --mode write)"
v="$(result_line --seed 7 --ops 400 --db "$work/wv.redb" --mode verify)"
echo "    write:  $w"
echo "    verify: $v"
if [[ "$w" != "$v" ]]; then
  echo "    MISMATCH: verify RESULT differs from write RESULT"
  fail=1
fi

# 3. thread count must not change the RESULT (readers only assert MVCC).
echo "==> [3] thread count does not affect the RESULT"
t1="$(result_line --seed 55 --ops 400 --db "$work/t1.redb" --mode full --threads 1)"
t8="$(result_line --seed 55 --ops 400 --db "$work/t8.redb" --mode full --threads 8)"
echo "    threads=1: $t1"
echo "    threads=8: $t8"
if [[ "$t1" != "$t8" ]]; then
  echo "    MISMATCH: RESULT depends on thread count"
  fail=1
fi

# 4. seed sweep: 5 seeds each reproduce byte-identically, and distinct seeds
#    produce distinct state hashes.
echo "==> [4] seed sweep: per-seed reproducible, cross-seed distinct"
declare -a states=()
for seed in 1 2 3 4 5; do
  first="$(result_line --seed "$seed" --ops 300 --db "$work/sweep-${seed}-a.redb" --mode full)"
  again="$(result_line --seed "$seed" --ops 300 --db "$work/sweep-${seed}-b.redb" --mode full)"
  echo "    seed $seed: $first"
  if [[ "$first" != "$again" ]]; then
    echo "    MISMATCH: seed $seed not reproducible"
    fail=1
  fi
  states+=("$(sed -n 's/.*state=\([0-9a-f]*\).*/\1/p' <<<"$first")")
done
distinct="$(printf '%s\n' "${states[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "$distinct" -ne "${#states[@]}" ]]; then
  echo "    WARNING: only $distinct distinct state hashes across ${#states[@]} seeds"
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "==> FAILED"
  exit 1
fi
echo "==> all native checks passed"
