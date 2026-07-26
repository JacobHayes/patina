#!/usr/bin/env bash
# Native (non-Patina) smoke test for the raft harness.
#
# Runs three scenarios against real threads and real loopback UDP:
#   1. healthy 3-node cluster commits every proposal;
#   2. one node is killed mid-run and the remaining two still commit;
#   3. one node is killed mid-run and RESTARTED: it reopens its FileStorage,
#      rejoins, catches up, and the cluster still commits every proposal
#      (crash-recovery, verified natively before the Patina campaign).
#
# The harness binary is 100% std-pure: it contains NO Patina imports and NO
# cfg(patina). The ONLY difference between a native and a Patina run is the
# runner command; the harness args are byte-for-byte identical. That runner is
# the single RUNNER variable below. To dry-run the Patina invocation instead
# (see run-patina.sh for the real thing):
#
#   RUNNER='cargo patina run --release --seed 1 --' ./run-native.sh
#
# Native runs are NOT seed-deterministic (real threads + UDP); determinism
# arrives only under Patina. What must hold here is that every run reaches
# `committed == proposals` with exit 0. All invariants live INSIDE the binary
# (it exits non-zero and prints RAFT_VIOLATION on any violation); this script
# only orchestrates and checks the exit code and the RAFT_RESULT line.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# The one seam between native and Patina. Word-split intentionally so it can
# carry flags (e.g. "cargo run --release --").
RUNNER="${RUNNER:-cargo run --release --}"
proposals=50

echo "==> runner: $RUNNER"
echo "==> building release binary"
cargo build --release

# run_scenario NAME EXTRA_ARGS...
run_scenario() {
  local name="$1"; shift
  local data_dir
  data_dir="$(mktemp -d)"
  trap 'rm -rf "$data_dir"' RETURN

  echo "==> scenario: $name"
  local output
  # RUNNER is deliberately unquoted so its words split into argv.
  # shellcheck disable=SC2086
  if ! output="$($RUNNER --proposals "$proposals" --data-dir "$data_dir" "$@")"; then
    echo "FAILED ($name): non-zero exit"
    echo "$output"
    return 1
  fi
  echo "$output"

  # Assert the summary line reports full commit.
  local committed
  committed="$(sed -n 's/.*committed=\([0-9][0-9]*\).*/\1/p' <<<"$output")"
  if [[ "$committed" != "$proposals" ]]; then
    echo "FAILED ($name): committed=$committed, expected $proposals"
    return 1
  fi
  echo "OK ($name): committed=$committed"
}

# Scenario 1: healthy cluster on ports 4001-4003.
run_scenario "healthy" --seed 1 --base-port 4001

# Scenario 2: kill node 3 one second in; nodes 1 and 2 (a quorum) must still
# commit every proposal. Separate port range avoids any lingering bind.
run_scenario "one-node-down" --seed 2 --base-port 4011 --kill-node 3 --kill-after-secs 1

# Scenario 3: crash-RECOVERY. Kill node 2 the moment the committed count reaches
# 10, then RESTART it after a short delay. The supervisor reopens FileStorage on
# node 2's SAME data dir (recovery reconstruction), rebinds its UDP port, and
# rejoins; node 2 must catch up the entries it missed while down and the cluster
# must still commit every proposal. `--propose-window` paces the client so the
# kill lands mid-run (native commits the whole batch in one burst otherwise),
# forcing genuine catch-up rather than a re-apply of an already-complete log.
# The RAFT_RESULT line reports `restarts=1`; run_scenario only asserts full
# commit and exit 0, and the binary's own invariant checks (log matching, no
# applied regress, single leader/term) hold ACROSS the restart or it exits
# non-zero with RAFT_VIOLATION.
run_scenario "kill-and-restart" --seed 3 --base-port 4021 \
  --kill-plan 2:10 --restart-after-ticks 5 --propose-window 3

echo "==> all native scenarios passed"
