#!/usr/bin/env bash
# Native (non-Patina) smoke test for workq.
#
# Runs the durable work queue against real threads, real loopback UDP, and the
# real filesystem, proving the harness itself is sound before any Patina campaign.
# Three scenarios:
#   1. a quiet run: every job is enqueued, processed, and completed, invariants
#      hold, exit 0;
#   2. crash-recovery: the server is killed mid-run and restarted on the same WAL
#      (--crash-at-completed); acked jobs survive and the run still converges;
#   3. the in-process fail-closed-recovery self-test (invariant 5).
#
# The binary is 100% std-pure (no Patina imports, no cfg(patina)); the ONLY
# difference between a native and a Patina run is the RUNNER command below. To
# dry-run the Patina invocation shape instead (see run-patina.sh for the real
# gate):
#
#   RUNNER='cargo patina run --release --seed 1 --' ./run-native.sh
#
# Native runs are NOT seed-deterministic (real threads + UDP); determinism
# arrives only under Patina. What must hold here is convergence + exit 0. All
# invariants live INSIDE the binary (it prints WORKQ_VIOLATION and exits nonzero
# on any breach); this script only orchestrates and checks the outcome.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# The one seam between native and Patina. Word-split intentionally so it can
# carry flags (e.g. "cargo run --release --").
RUNNER="${RUNNER:-cargo run --release --}"
JOBS=32
COMMON=(--jobs "$JOBS" --workers 4 --producers 2 --timeout-secs 60)

echo "==> runner: $RUNNER"
echo "==> building release binary"
cargo build --release

# run_scenario NAME BASE_PORT EXTRA_ARGS...
run_scenario() {
  local name="$1" port="$2"; shift 2
  local data_dir
  data_dir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$data_dir'" RETURN

  echo "==> scenario: $name"
  local output
  # RUNNER is deliberately unquoted so its words split into argv.
  # shellcheck disable=SC2086
  if ! output="$($RUNNER "${COMMON[@]}" --base-port "$port" --data-dir "$data_dir" "$@")"; then
    echo "FAILED ($name): non-zero exit"; echo "$output"; return 1
  fi
  echo "$output"

  local enq comp failed
  enq="$(sed -n 's/.*enqueued=\([0-9][0-9]*\).*/\1/p' <<<"$output")"
  comp="$(sed -n 's/.*completed=\([0-9][0-9]*\).*/\1/p' <<<"$output")"
  failed="$(sed -n 's/.*failed=\([0-9][0-9]*\).*/\1/p' <<<"$output")"
  if [[ "$enq" != "$JOBS" ]]; then
    echo "FAILED ($name): enqueued=$enq expected $JOBS"; return 1
  fi
  if [[ $(( comp + failed )) -ne "$JOBS" ]]; then
    echo "FAILED ($name): did not converge (completed=$comp failed=$failed)"; return 1
  fi
  echo "OK ($name): enqueued=$enq completed=$comp failed=$failed"
}

# 1. Quiet run: no faults, so every job should complete (nothing failed).
run_scenario "healthy" 5301 --seed 1

# 2. Crash-recovery: kill + restart the server once 8 jobs have completed. The
#    supervisor reopens the WAL on the same data dir; acked jobs survive and the
#    cluster still converges. run_scenario checks convergence and exit 0; the
#    binary's own invariant checks (durability, exactly-once, no-loss) hold across
#    the restart or it exits non-zero with WORKQ_VIOLATION.
run_scenario "crash-recovery" 5311 --seed 2 --crash-at-completed 8

# 3. The in-process fail-closed-recovery self-test (invariant 5).
echo "==> scenario: recovery-fail-closed selftest"
# shellcheck disable=SC2086
if out="$($RUNNER --check-recovery-fail-closed)"; then
  echo "$out"; echo "OK (recovery-fail-closed selftest)"
else
  echo "FAILED (recovery-fail-closed selftest)"; echo "$out"; exit 1
fi

echo "==> all native scenarios passed"
