#!/usr/bin/env bash
# Patina's local landing gate (`mise run check`). Successful rungs are silent;
# a failed rung replays its command and complete log. Every rung's log, with its
# timing, is kept in the directory the OVERALL line names.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

check_target_base="$root/target/check"
export CARGO_TARGET_DIR="$check_target_base/serial"
# Every guest a check builds (the workspace suite's and every testbed rung's)
# shares the native shim builds of the serial target, whatever target dir the
# guest itself builds in, so a check builds each shim profile once.
export PATINA_SHIM_TARGET_DIR="$CARGO_TARGET_DIR"
# One test process per Cargo build job by default: a test can start guest
# builds of its own, so this keeps the suite inside the build cap the host
# already sets. NEXTEST_TEST_THREADS (nextest's own variable) overrides it.
test_threads=${NEXTEST_TEST_THREADS:-${CARGO_BUILD_JOBS:-$(( ($(getconf _NPROCESSORS_ONLN) + 1) / 2 ))}}
# Host clippy plus cross-cfg passes for the other OS family and, on Linux, the
# other Linux architecture: per-architecture constants and syscall tables
# (aarch64 has no epoll_wait or open, and a different O_DIRECTORY) otherwise
# fail only in CI's native gates job.
case "$(uname -s)/$(uname -m)" in
  Darwin/*) cross_clippy=(x86_64-unknown-linux-gnu) ;;
  Linux/aarch64) cross_clippy=(aarch64-apple-darwin x86_64-unknown-linux-gnu) ;;
  *) cross_clippy=(aarch64-apple-darwin aarch64-unknown-linux-gnu) ;;
esac

# The native ecosystem testbeds, one after another; the SUD-only ones (and Go,
# whose runtime issues raw syscalls) run only on x86_64 Linux.
native_testbeds() {
  testbeds/fifo-ipc/run-patina.sh || return
  [[ $(uname -s)/$(uname -m) == Linux/x86_64 ]] || return 0
  testbeds/rustix-default/run-patina.sh &&
    testbeds/cap-std-dirfd/run-patina.sh &&
    testbeds/go-guest/run-patina.sh
}

logs=$(mktemp -d "${TMPDIR:-/tmp}/patina-check.XXXXXX") || exit 1
total_start=$(date +%s)
passed=0
pids=()
labels=()
commands=()
log_paths=()
status_paths=()
start_times=()

finish() {
  local status=$?
  local result=PASS
  ((status == 0)) || result=FAIL
  printf 'OVERALL %s (passed=%s; %ss); logs: %s\n' \
    "$result" "$passed" "$(( $(date +%s) - total_start ))" "$logs"
}

stop_children() {
  local pid
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}

trap finish EXIT
trap 'stop_children; exit 130' INT
trap 'stop_children; exit 143' TERM

quote_command() {
  local arg
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
}

rung_slug() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-//; s/-$//'
}

run_rung() {
  local label=$1
  shift
  local log="$logs/$(rung_slug "$label").log"
  local start end status
  start=$(date +%s)
  { printf 'command:'; quote_command "$@"; printf '\n'; } >"$log"
  "$@" >>"$log" 2>&1
  status=$?
  end=$(date +%s)
  printf 'exit=%s elapsed=%ss\n' "$status" "$((end - start))" >>"$log"
  if ((status != 0)); then
    printf 'FAIL  %s (%ss; exit %d)\ncommand:' "$label" "$((end - start))" "$status" >&2
    quote_command "$@" >&2
    printf '\n--- failure log ---\n' >&2
    cat "$log" >&2
    return "$status"
  fi
  passed=$((passed + 1))
}

# A parallel rung in a Cargo target dir of its own under target/check/parallel/.
start_rung() {
  start_rung_in "$check_target_base/parallel/$(rung_slug "$1")" "$@"
}

start_rung_in() {
  local target_dir=$1 label=$2
  shift 2
  local index=${#pids[@]}
  local log="$logs/$(rung_slug "$label").log"
  local status_file="$logs/parallel-$index.status"
  local arg command
  printf -v command 'CARGO_TARGET_DIR=%q' "$target_dir"
  for arg in "$@"; do
    printf -v command '%s %q' "$command" "$arg"
  done
  labels+=("$label")
  commands+=("$command")
  log_paths+=("$log")
  status_paths+=("$status_file")
  start_times+=("$(date +%s)")
  (
    printf 'command: %s\n' "$command" >"$log"
    CARGO_TARGET_DIR="$target_dir" "$@" >>"$log" 2>&1
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
    printf 'exit=%s elapsed=%ss\n' "$status" "$((end - start_times[$i]))" >>"${log_paths[$i]}"
    if ((status == 0)); then
      passed=$((passed + 1))
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

workspace_nextest() {
  cargo nextest run --profile local --locked --test-threads "$test_threads" "$@"
}

run_full() {
  # Cheap, high-signal failures stay serial and stop before expensive work.
  run_rung 'syscall generator offline detectors' python3 -B scripts/test-refresh-syscalls.py || return $?
  run_rung 'format' cargo fmt --all -- --check || return $?
  run_rung 'structural lints' scripts/check-structure.sh || return $?
  run_rung 'host clippy' cargo clippy --workspace --all-targets --locked -- -D warnings || return $?
  for target in "${cross_clippy[@]}"; do
    run_rung "$target clippy" cargo clippy --workspace --all-targets --locked --target "$target" -- -D warnings || return $?
  done
  run_rung 'documentation' cargo doc --workspace --no-deps --locked || return $?
  run_rung 'multiproc classifier selftest' testbeds/multiproc/run-patina.sh --selftest || return $?
  run_rung 'workq classifier selftest' testbeds/workq/fuzz-sweep.sh --selftest || return $?
  run_rung 'wasi buggify sweep selftest' testbeds/buggify-wasi/wasi-buggify-sweep.sh --selftest || return $?
  run_rung 'macro feature test' cargo test --quiet -p patina-dst --features macros --locked || return $?
  # One build of the workspace suite; its cargo-patina (the test profile, which
  # optimizes the third-party crates and the guest scanner) drives every testbed.
  run_rung 'workspace test build' workspace_nextest --workspace --no-run || return $?

  # The workspace suite (the native_conformance scenarios included) and every
  # remaining gate run at once. The suite holds a fixed number of test slots and
  # leaves cores idle, and the testbeds are mostly one guest run after another,
  # so overlapping them costs the suite little and saves the testbeds' wall
  # time. Every guest shares the native shim builds (PATINA_SHIM_TARGET_DIR),
  # so a shim the suite is building is waited for, never built twice. Each
  # testbed gets a Cargo target dir of its own through start_rung, plus each
  # script's own runtime scratch paths. The multiproc pending-gap battery runs
  # in CI.
  start_rung_in "$CARGO_TARGET_DIR" 'workspace tests (includes e2e)' workspace_nextest --workspace
  start_rung_in "$CARGO_TARGET_DIR" 'doctests' cargo test --quiet --doc --workspace --locked
  # Every workspace member packages cleanly (manifest metadata, readme paths,
  # include/exclude). --no-verify skips the per-crate verify build; the release
  # dry run (scripts/publish.sh) covers that and the license-text audit.
  start_rung_in "$CARGO_TARGET_DIR" 'crate packaging' cargo package --workspace --no-verify --locked --allow-dirty
  export PATINA_CLI="$CARGO_TARGET_DIR/debug/cargo-patina"
  start_rung 'native ecosystem testbeds' native_testbeds
  start_rung 'workq testbed' testbeds/workq/run-patina.sh
  start_rung 'macro adopter testbed' testbeds/patina-macro-adopter/run.sh
  start_rung 'pubsub testbed' testbeds/pubsub/run-patina.sh
  start_rung 'cross-target smoke' scripts/smoke-cross-target.sh
  start_rung 'WASI validation' scripts/validate-wasi.sh
  wait_rungs || return $?
}

run_full
