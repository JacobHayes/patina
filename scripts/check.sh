#!/usr/bin/env bash
# Timed, quiet orchestration for Patina's local validation gates.
# Successful command output is suppressed; a failure replays its complete log.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

usage() {
  cat <<'EOF'
Usage: scripts/check.sh <full|fast|msrv>

  full  Full pre-landing gate. Cheap checks run first, then independent
        heavyweight gates run concurrently.
  fast  Inner-loop gate; not sufficient for landing.
  msrv  Execute the complete test suite on the documented MSRV.

Successful rung logs are hidden. On failure, the complete rung log and exact
command are printed. PATINA_CHECK_JOBS is intentionally not exposed: the full
profile uses bounded, reviewed concurrency groups whose members have independent
scratch/output paths.
EOF
}

case ${1:-} in
  full|fast|msrv) profile=$1 ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

logs=$(mktemp -d "${TMPDIR:-/tmp}/patina-check.XXXXXX")
pids=()
labels=()
commands=()
log_paths=()
status_paths=()
start_times=()

cleanup() {
  rm -rf "$logs"
}

stop_children() {
  local pid
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}

trap cleanup EXIT
trap 'stop_children; exit 130' INT
trap 'stop_children; exit 143' TERM

quote_command() {
  local arg
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
}

run_rung() {
  local label=$1
  shift
  local log="$logs/serial.log"
  local start end status
  printf 'START %s\n' "$label"
  start=$(date +%s)
  "$@" >"$log" 2>&1
  status=$?
  end=$(date +%s)
  if ((status != 0)); then
    printf 'FAIL  %s (%ss; exit %d)\ncommand:' "$label" "$((end - start))" "$status" >&2
    quote_command "$@" >&2
    printf '\n--- failure log ---\n' >&2
    cat "$log" >&2
    return "$status"
  fi
  printf 'PASS  %s (%ss)\n' "$label" "$((end - start))"
}

start_rung() {
  local label=$1
  shift
  local index=${#pids[@]}
  local log="$logs/parallel-$index.log"
  local status_file="$logs/parallel-$index.status"
  local command
  printf -v command '%q ' "$@"
  printf 'START %s [parallel]\n' "$label"
  labels+=("$label")
  commands+=("$command")
  log_paths+=("$log")
  status_paths+=("$status_file")
  start_times+=("$(date +%s)")
  (
    "$@" >"$log" 2>&1
    local_status=$?
    printf '%s %s\n' "$local_status" "$(date +%s)" >"$status_file"
    exit "$local_status"
  ) &
  pids+=("$!")
}

wait_rungs() {
  local i wait_status status end failed=0
  for i in "${!pids[@]}"; do
    wait_status=0
    wait "${pids[$i]}" || wait_status=$?
    if [[ ! -r ${status_paths[$i]} ]]; then
      status=$wait_status
      end=$(date +%s)
    else
      read -r status end <"${status_paths[$i]}"
    fi
    if ((status == 0)); then
      printf 'PASS  %s (%ss)\n' "${labels[$i]}" "$((end - start_times[$i]))"
    else
      failed=1
      printf 'FAIL  %s (%ss; exit %d)\ncommand: %s\n--- failure log ---\n' \
        "${labels[$i]}" "$((end - start_times[$i]))" "$status" "${commands[$i]}" >&2
      cat "${log_paths[$i]}" >&2
    fi
  done
  pids=()
  labels=()
  commands=()
  log_paths=()
  status_paths=()
  start_times=()
  ((failed == 0))
}

run_msrv() {
  cargo +1.86.0 test --workspace --locked &&
    cargo +1.86.0 test -p patina-dst --features macros --locked
}

run_full() {
  local total_start
  total_start=$(date +%s)

  # Cheap, high-signal failures stay serial and stop before expensive work.
  run_rung 'format' cargo fmt --all -- --check || return $?
  run_rung 'host clippy' cargo clippy --workspace --all-targets --locked -- -D warnings || return $?
  run_rung 'Linux-cfg clippy' cargo clippy --workspace --all-targets --locked --target x86_64-unknown-linux-gnu -- -D warnings || return $?
  run_rung 'documentation' cargo doc --workspace --no-deps --locked || return $?
  run_rung 'CLI flag drift' scripts/check-flag-drift.sh || return $?
  run_rung 'workq classifier selftest' testbeds/workq/fuzz-sweep.sh --selftest || return $?
  run_rung 'campaign classifier selftest' cargo run -q -p cargo-patina -- patina campaign --selftest || return $?

  # Stable workspace tests and native validation use independent scratch paths
  # and the same toolchain. Keep the pair explicit and bounded: a broader fan-out
  # oversubscribed the host and made the macro-adopter's nested Cargo run contend.
  start_rung 'stable workspace tests' cargo test --workspace --locked
  start_rung 'native-shim validation' scripts/validate-native-shim.sh
  wait_rungs || return $?

  # Keep MSRV serial. Its e2e tests spawn nested cargo-patina builds that resolve
  # the repository's root shim, so an outer Cargo cache cannot isolate every
  # artifact and concurrent rustc versions can produce invalid mixed archives.
  run_rung 'MSRV workspace tests' run_msrv || return $?
  # Restore the stable root artifacts before stable-toolchain testbeds consume
  # them. Cargo fingerprints the toolchain transition and rebuilds as needed.
  run_rung 'restore stable artifacts' cargo build --locked -p patina-dst-native-shim -p cargo-patina || return $?

  # The remaining stable-toolchain suites have separate temp/testbed outputs.
  # Their combined serial cost is small, but overlapping them removes it from
  # the critical path without competing with the two CPU-heavy suites above.
  start_rung 'patina-dst macro feature tests' cargo test -p patina-dst --features macros --locked
  start_rung 'macro adopter testbed' testbeds/patina-macro-adopter/run.sh
  start_rung 'pubsub testbed' testbeds/pubsub/run-patina.sh
  start_rung 'workq testbed' testbeds/workq/run-patina.sh
  start_rung 'WASI validation' scripts/validate-wasi.sh
  start_rung 'cross-target smoke' scripts/smoke-cross-target.sh
  wait_rungs || return $?

  printf 'PASS  full landing gate (%ss total)\n' "$(( $(date +%s) - total_start ))"
}

run_fast() {
  local total_start
  total_start=$(date +%s)
  run_rung 'format' cargo fmt --all -- --check || return $?
  run_rung 'host clippy' cargo clippy --workspace --all-targets --locked -- -D warnings || return $?
  run_rung 'Linux-cfg clippy' cargo clippy --workspace --all-targets --locked --target x86_64-unknown-linux-gnu -- -D warnings || return $?
  start_rung 'workspace tests (fast exclusions)' cargo test --workspace --locked -- \
    --skip native_two_axis_stateful_shrink_then_schedule_minimize \
    --skip minimize_canonicalizes_a_recorded_schedule_via_replay_oracle \
    --skip native_proptest_case_generation
  start_rung 'WASI validation' scripts/validate-wasi.sh
  start_rung 'cross-target smoke' scripts/smoke-cross-target.sh
  wait_rungs || return $?
  printf 'PASS  fast check (%ss total)\n' "$(( $(date +%s) - total_start ))"
}

case $profile in
  full) run_full ;;
  fast) run_fast ;;
  msrv) run_rung 'MSRV compatibility' run_msrv ;;
esac
