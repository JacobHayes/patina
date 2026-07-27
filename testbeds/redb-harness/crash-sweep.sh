#!/usr/bin/env bash
###############################################################################
# redb crash-injection campaign under Patina.
#
# Sweeps `--fs-crash-at {write,sync,close}:N` across ordinals and Patina seeds,
# under BOTH torn-write granularities:
#
#   block  the default whole-block model: a torn page reverts entirely to the
#          durable image, so a crash only ever exposes a crash-consistent block
#          prefix or a cleanly-rejected image.
#   byte   sub-block tearing (`--fs-torn-granularity byte`): the final unsynced
#          page may survive PARTIALLY -- a seeded prefix of the write persists
#          and the suffix reverts -- modeling a torn in-flight page whose header
#          and body disagree. This is the geometry that can trip redb's
#          open-time recovery assert, which whole-block tearing never reaches.
#
# The harness runs in `crash` mode (write + cold reopen in one process, since the
# in-memory crash filesystem does not survive a process exit). Each run prints
# one CRASH line whose `outcome=` field classifies the recovered state:
#
#   NO_CRASH     the ordinal was past the run; workload completed, full state
#   HOLDS        reopen exposed a committed prefix keeping every acked commit
#   LOST_COMMIT  reopen lost a commit redb had acknowledged durable   (redb BUG)
#   TORN_STATE   reopen exposed a state that was never a valid prefix  (redb BUG)
#   OPEN_ERR     Database::open returned Err on the crashed image
#   OPEN_PANIC   Database::open panicked (redb's internal recovery assert)
#
# The script tabulates the outcomes per granularity and EXITS NONZERO if any
# LOST_COMMIT/TORN_STATE (a real durability bug) is seen -- the jackpot the
# campaign hunts. An OPEN_PANIC is the sub-block campaign's target artifact
# (redb's known open-time assert): each is preserved by re-recording a
# self-contained trace under crash-artifacts/, and the exact FLAG-FREE replay
# command is printed. An OPEN_PANIC is a robustness finding, reported loudly but
# not, on its own, a regression exit.
###############################################################################
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
harness_dir="$repo_root/testbeds/redb-harness"
built_bin="$harness_dir/target/patina/redb-harness"
artifacts_dir="$harness_dir/crash-artifacts"
PATINA="$repo_root/target/release/cargo-patina"

# Workload knobs. A moderate op count gives ~30-60 commits and plenty of
# write/sync/close boundary ops for the ordinal sweep to land inside.
WORKLOAD_SEED="${WORKLOAD_SEED:-42}"
OPS="${OPS:-400}"

# Ordinals per op kind and Patina (fault) seeds. Under two granularities the
# product stays a few hundred runs.
WRITE_ORDS="${WRITE_ORDS:-1 3 6 10 16 24 34 48 64 90 120 160 220 300}"
SYNC_ORDS="${SYNC_ORDS:-1 2 3 5 8 12 18 26 36 50}"
CLOSE_ORDS="${CLOSE_ORDS:-1 2 3 4 6 8}"
FAULT_SEEDS="${FAULT_SEEDS:-0 1 2}"
# Torn-write granularities to sweep. `byte` is the sub-block redb-panic hunt;
# override to just `block` for the legacy whole-block campaign.
GRANULARITIES="${GRANULARITIES:-block byte}"

cd "$repo_root"

echo "==> building cargo-patina (embeds the shim) and the harness under Patina"
cargo build --release --quiet -p cargo-patina
mkdir -p "$harness_dir/target/patina" "$artifacts_dir"
"$PATINA" patina build "$harness_dir" \
  --output "$built_bin" --release >/dev/null

declare -A tally=()
declare -a bugs=()
declare -a panics=()
runs=0

# Re-record a notable run as a self-contained trace and emit the flag-free
# replay command. The recorded trace carries the fault configuration AND the
# guest arguments in its metadata, so `cargo patina replay` needs no
# --fs-crash-at/--fs-torn-granularity flags and no `-- ...` argument section.
preserve() {
  local spec="$1" fseed="$2" gran="$3" kind="$4"
  local safe_spec="${spec/:/-}"
  local trace="$artifacts_dir/${kind}_${gran}_${safe_spec}_seed${fseed}.patina"
  rm -f "$trace"
  local crash_flags=(--fs-crash-at "$spec")
  [[ "$gran" == "byte" ]] && crash_flags+=(--fs-torn-granularity byte)
  "$PATINA" patina run "$built_bin" --seed "$fseed" \
    "${crash_flags[@]}" --record "$trace" -- \
    --seed "$WORKLOAD_SEED" --ops "$OPS" --db /db/redb.redb --mode crash --threads 1 \
    >/dev/null 2>&1 || true
  if [[ -f "$trace" ]]; then
    echo "       preserved trace: $trace"
    echo "       flag-free replay: $PATINA patina replay $built_bin $trace"
  fi
}

run_one() {
  local spec="$1" fseed="$2" gran="$3"
  local line crash_flags=(--fs-crash-at "$spec")
  [[ "$gran" == "byte" ]] && crash_flags+=(--fs-torn-granularity byte)
  # crash mode owns its exit code; capture the line regardless of code.
  line="$("$PATINA" patina run "$built_bin" --seed "$fseed" \
    "${crash_flags[@]}" -- \
    --seed "$WORKLOAD_SEED" --ops "$OPS" --db /db/redb.redb --mode crash --threads 1 \
    2>/dev/null || true)"
  local outcome
  outcome="$(sed -n 's/.*outcome=\([A-Z_]*\).*/\1/p' <<<"$line")"
  if [[ -z "$outcome" ]]; then
    outcome="NO_LINE"
    echo "    !! no CRASH line for gran=$gran spec=$spec fseed=$fseed" >&2
  fi
  tally["$gran/$outcome"]=$(( ${tally["$gran/$outcome"]:-0} + 1 ))
  runs=$(( runs + 1 ))
  if [[ "$outcome" == "LOST_COMMIT" || "$outcome" == "TORN_STATE" ]]; then
    bugs+=("gran=$gran spec=$spec fseed=$fseed :: $line")
    echo "    ** DURABILITY VIOLATION gran=$gran spec=$spec seed=$fseed" >&2
    preserve "$spec" "$fseed" "$gran" "bug"
  elif [[ "$outcome" == "OPEN_PANIC" ]]; then
    panics+=("gran=$gran spec=$spec fseed=$fseed :: $line")
    echo "    ** OPEN_PANIC (redb open-time assert) gran=$gran spec=$spec seed=$fseed" >&2
    preserve "$spec" "$fseed" "$gran" "openpanic"
  fi
  printf '    %-5s %-10s seed=%s -> %s\n' "$gran" "$spec" "$fseed" "$line"
}

for gran in $GRANULARITIES; do
  echo "==> sweeping write ordinals (granularity=$gran)"
  for n in $WRITE_ORDS; do for s in $FAULT_SEEDS; do run_one "write:$n" "$s" "$gran"; done; done
  echo "==> sweeping sync ordinals (granularity=$gran)"
  for n in $SYNC_ORDS; do for s in $FAULT_SEEDS; do run_one "sync:$n" "$s" "$gran"; done; done
  echo "==> sweeping close ordinals (granularity=$gran)"
  for n in $CLOSE_ORDS; do for s in $FAULT_SEEDS; do run_one "close:$n" "$s" "$gran"; done; done
done

echo
echo "==> crash-injection tabulation ($runs runs, workload seed=$WORKLOAD_SEED ops=$OPS)"
for gran in $GRANULARITIES; do
  echo "    granularity=$gran"
  for outcome in NO_CRASH HOLDS LOST_COMMIT TORN_STATE OPEN_ERR OPEN_PANIC NO_LINE; do
    count="${tally[$gran/$outcome]:-0}"
    [[ "$count" -gt 0 ]] && printf '        %-12s %d\n' "$outcome" "$count"
  done
done

if [[ "${#panics[@]}" -gt 0 ]]; then
  echo
  echo "==> OPEN_PANIC reproductions (redb's internal open-time recovery assert):"
  printf '    %s\n' "${panics[@]}"
  echo "    (preserved traces + flag-free replay commands printed above; NOT filed upstream)"
fi

if [[ "${#bugs[@]}" -gt 0 ]]; then
  echo
  echo "==> DURABILITY VIOLATION(S) FOUND -- redb lost or tore an acknowledged commit:"
  printf '    %s\n' "${bugs[@]}"
  echo "==> FAILED (real redb durability bug)"
  exit 1
fi
echo "==> no durability violations: every acknowledged commit survived every crash point"
