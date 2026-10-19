#!/usr/bin/env bash
# Timed, quiet orchestration for Patina's local validation gates.
# Successful command output is suppressed; a failure replays its complete log.
#
# This script stays deliberately small-but-real because mise's task runner can
# sequence tasks, limit jobs, print timings, and choose output styles, but it
# cannot currently provide Patina's required output contract: hide successful
# rung logs while replaying a failed rung's complete stdout/stderr. Keep the
# ladder here until mise grows that behavior.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

check_target_base="$root/target/check"
export CARGO_TARGET_DIR="$check_target_base/serial"
# The workspace suite's own cargo-patina (the test profile, which optimizes the
# third-party crates and the guest scanner) drives every gate that needs a CLI,
# so a check builds the CLI once. Every testbed rung's guests share the native
# shim builds of the serial target, which the suite's own guests fill.
patina_cli="$CARGO_TARGET_DIR/debug/cargo-patina"
# Testbed rungs only: the workspace suite's tests place shims themselves.
testbed_env=(env PATINA_CLI="$patina_cli" PATINA_SHIM_TARGET_DIR="$CARGO_TARGET_DIR")
# One test process per Cargo build job by default: a test can start guest
# builds of its own, so this keeps the suite inside the build cap the host
# already sets. NEXTEST_TEST_THREADS (nextest's own variable) overrides it.
test_threads=${NEXTEST_TEST_THREADS:-${CARGO_BUILD_JOBS:-$(( ($(getconf _NPROCESSORS_ONLN) + 1) / 2 ))}}
# Host clippy plus one cross-cfg pass for the other OS family. CI's gates job
# lints both Linux architectures natively.
if [[ $(uname -s) == Darwin ]]; then
  cross_clippy=('Linux-cfg clippy' x86_64-unknown-linux-gnu)
else
  cross_clippy=('Darwin-cfg clippy' aarch64-apple-darwin)
fi

usage() {
  cat <<'EOF'
Usage: scripts/check.sh <full|fast>
       scripts/check.sh --selftest

  full  Full local pre-landing gate. Cheap checks, host and cross-cfg clippy,
        docs and packaging run first, then one build of the workspace suite,
        whose cargo-patina drives the CLI gates. The workspace suite (nextest,
        e2e and native acceptance included) then runs alone; the doctests,
        WASI and cross-target smoke, and the native ecosystem, workq, pubsub
        and macro-adopter testbeds follow it concurrently.
  fast  Inner-loop gate; excludes cargo-patina end_to_end and the seven native
        execution targets and the landing-only docs/packaging/testbed rungs.
        Targeted native ABI feedback: mise run check:native-abi.

Successful rungs are silent; the overall result includes retained logs with
per-rung commands and timings, and counts the conformance scenarios the host
could not judge (NOT RUN, named on the next line). The full profile requires a
host oracle (PATINA_REQUIRE_HOST_ORACLE=1, as CI sets; set it to 0 to relax):
a NOT RUN other than a missing hardware feature fails it. On failure, the
complete rung log and exact command are printed. The workspace suite runs
under nextest (profile `local`) with NEXTEST_TEST_THREADS tests at a time,
else one per CARGO_BUILD_JOBS job, else one per two CPUs. Serial work, the workspace suite and the doctests share one Cargo
target dir; every other parallel rung gets its own under
target/check/parallel/, plus the suite's cargo-patina (PATINA_CLI) and shim
builds (PATINA_SHIM_TARGET_DIR).
PATINA_CHECK_JOBS is intentionally not exposed: the full profile uses one
reviewed concurrency group whose members have independent scratch/output paths.
EOF
}

case ${1:-} in
  full|fast) profile=$1 ;;
  --selftest) profile=selftest ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

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
  # The harness prints `NOT RUN <scenario>: <reason>` past libtest's capture,
  # so the line can start mid-line after progress dots.
  local not_run
  not_run=$(cat "$logs"/*.log 2>/dev/null | grep -o 'NOT RUN [^:]*' | sort -u)
  printf 'OVERALL %s %s (passed=%s not_run=%s; %ss); logs: %s\n' \
    "$result" "$profile" "$passed" "$(grep -c . <<<"$not_run")" \
    "$(( $(date +%s) - total_start ))" "$logs"
  [[ -z $not_run ]] || printf '%s\n' "$not_run"
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

run_fast_workspace_tests() {
  # Keep the expensive execution targets in the full and focused gates.
  # Enumerate the remaining cargo-patina targets alongside the other packages.
  local cargo_patina_targets=(--lib --bin cargo-patina)
  local test_path test_name
  while IFS= read -r test_path; do
    test_name=$(basename "${test_path%.rs}")
    case "$test_name" in
      native_abi|native_conformance|native_containment|native_raw|native_signals|native_trace|native_workloads) continue ;;
    esac
    cargo_patina_targets+=(--test "$test_name")
  done < <(find crates/cargo-patina/tests -maxdepth 1 -type f -name '*.rs' ! -name end_to_end.rs | LC_ALL=C sort)

  workspace_nextest --workspace --exclude cargo-patina &&
    workspace_nextest -p cargo-patina "${cargo_patina_targets[@]}" &&
    cargo test --quiet --doc --workspace --locked
}

# Class detector: successful child chatter stays in retained logs, while failed
# children preserve their status, command, and original stdout/stderr.
output_selftest() (
  local output="$logs/output-selftest.console" status
  passed=0
  run_rung 'planted success' bash -c 'echo success-stdout; echo success-stderr >&2' >"$output" 2>&1
  if [[ -s "$output" || $passed != 1 ]] ||
      ! grep -q success-stderr "$logs/planted-success.log"; then
    echo 'FAIL: successful rung was noisy or lost its log/count' >&2; return 1
  fi
  run_rung 'planted failure' bash -c 'echo failure-stdout; echo failure-stderr >&2; exit 7' >"$output" 2>&1
  status=$?
  if [[ $status != 7 ]] || ! grep -q failure-stdout "$output" ||
      ! grep -q failure-stderr "$output" || ! grep -q 'command:' "$output"; then
    echo 'FAIL: failed rung lost its status, command, or output' >&2; return 1
  fi
  start_rung 'parallel success' bash -c 'echo parallel-success' >"$output" 2>&1
  wait_rungs >>"$output" 2>&1
  if [[ -s "$output" || $passed != 2 ]] ||
      ! grep -q parallel-success "$logs/parallel-success.log"; then
    echo 'FAIL: successful parallel rung was noisy or lost its log/count' >&2; return 1
  fi
  start_rung 'parallel failure' bash -c 'echo parallel-stderr >&2; exit 9' >"$output" 2>&1
  wait_rungs >>"$output" 2>&1
  status=$?
  if [[ $status == 0 || $passed != 2 ]] || ! grep -q parallel-stderr "$output" ||
      ! grep -q 'exit 9' "$output"; then
    echo 'FAIL: failed parallel rung lost its failure or output' >&2; return 1
  fi
)

run_full() {
  # Cheap, high-signal failures stay serial and stop before expensive work.
  run_rung 'output contract selftest' output_selftest || return $?
  run_rung 'toolchain pin drift' python3 -B scripts/check-toolchain.py || return $?
  run_rung 'toolchain pin drift selftest' python3 -B scripts/check-toolchain.py --selftest || return $?
  run_rung 'syscall generator offline detectors' python3 -B scripts/test-refresh-syscalls.py || return $?
  run_rung 'benchmark statistics tests' python3 -B scripts/test-bench.py || return $?
  run_rung 'file-size ratchet' python3 -B scripts/check-file-size.py || return $?
  run_rung 'file-size ratchet selftest' python3 -B scripts/check-file-size.py --selftest || return $?
  run_rung 'format' cargo fmt --all -- --check || return $?
  run_rung 'structural lints' scripts/check-structure.sh || return $?
  run_rung 'host clippy' cargo clippy --workspace --all-targets --locked -- -D warnings || return $?
  run_rung "${cross_clippy[0]}" cargo clippy --workspace --all-targets --locked --target "${cross_clippy[1]}" -- -D warnings || return $?
  run_rung 'documentation' cargo doc --workspace --no-deps --locked || return $?
  # Every workspace member packages cleanly (manifest metadata, readme paths,
  # include/exclude). --no-verify skips the per-crate verify build; the release
  # dry run (scripts/publish.sh) covers that and the license-text audit.
  run_rung 'crate packaging' cargo package --workspace --no-verify --locked --allow-dirty || return $?
  run_rung 'multiproc classifier selftest' testbeds/multiproc/run-patina.sh --selftest || return $?
  run_rung 'workq classifier selftest' testbeds/workq/fuzz-sweep.sh --selftest || return $?
  run_rung 'wasi buggify sweep selftest' testbeds/buggify-wasi/wasi-buggify-sweep.sh --selftest || return $?
  run_rung 'macro feature test' cargo test --quiet -p patina-dst --features macros --locked || return $?
  # One build of the workspace suite; its cargo-patina drives every later gate.
  run_rung 'workspace test build' workspace_nextest --workspace --no-run || return $?
  run_rung 'CLI flag drift' env PATINA_CLI="$patina_cli" scripts/check-flag-drift.sh || return $?
  run_rung 'campaign classifier selftest' "$patina_cli" patina campaign --selftest || return $?

  # The workspace suite (the native_conformance scenarios included) runs alone:
  # its guests fill the shared native shim builds, so the testbeds that follow
  # it, all at once, reuse them instead of building them alongside it. Measured
  # fresh, that matches overlapping the two in wall time and uses less CPU. Each
  # testbed gets a Cargo target dir of its own through start_rung, plus each
  # script's own runtime scratch paths. The multiproc pending-gap battery runs
  # in CI.
  run_rung 'workspace tests (includes e2e)' workspace_nextest --workspace || return $?
  start_rung 'native ecosystem testbeds' "${testbed_env[@]}" scripts/check-native-testbeds.sh
  start_rung 'workq testbed' "${testbed_env[@]}" testbeds/workq/run-patina.sh
  start_rung 'macro adopter testbed' "${testbed_env[@]}" testbeds/patina-macro-adopter/run.sh
  start_rung 'pubsub testbed' "${testbed_env[@]}" testbeds/pubsub/run-patina.sh
  start_rung 'cross-target smoke' "${testbed_env[@]}" scripts/smoke-cross-target.sh
  start_rung 'WASI validation' "${testbed_env[@]}" scripts/validate-wasi.sh
  start_rung_in "$CARGO_TARGET_DIR" 'doctests' cargo test --quiet --doc --workspace --locked
  wait_rungs || return $?
}

run_fast() {
  run_rung 'output contract selftest' output_selftest || return $?
  run_rung 'toolchain pin drift' python3 -B scripts/check-toolchain.py || return $?
  run_rung 'toolchain pin drift selftest' python3 -B scripts/check-toolchain.py --selftest || return $?
  run_rung 'syscall generator offline detectors' python3 -B scripts/test-refresh-syscalls.py || return $?
  run_rung 'benchmark statistics tests' python3 -B scripts/test-bench.py || return $?
  run_rung 'file-size ratchet' python3 -B scripts/check-file-size.py || return $?
  run_rung 'file-size ratchet selftest' python3 -B scripts/check-file-size.py --selftest || return $?
  run_rung 'format' cargo fmt --all -- --check || return $?
  run_rung 'structural lints' scripts/check-structure.sh || return $?
  run_rung 'host clippy' cargo clippy --workspace --all-targets --locked -- -D warnings || return $?
  run_rung "${cross_clippy[0]}" cargo clippy --workspace --all-targets --locked --target "${cross_clippy[1]}" -- -D warnings || return $?

  # The fast test rung is cargo-heavy enough to inflate every other cargo-using
  # smoke when overlapped, even though it no longer contains the e2e binary.
  # Run it alone, then group the short independent smoke/selftest rungs. Its
  # cargo-patina drives the CLI gates after it.
  run_rung 'workspace tests (no e2e/native execution targets)' run_fast_workspace_tests || return $?
  run_rung 'CLI flag drift' env PATINA_CLI="$patina_cli" scripts/check-flag-drift.sh || return $?
  run_rung 'multiproc classifier selftest' testbeds/multiproc/run-patina.sh --selftest || return $?
  run_rung 'workq classifier selftest' testbeds/workq/fuzz-sweep.sh --selftest || return $?
  run_rung 'wasi buggify sweep selftest' testbeds/buggify-wasi/wasi-buggify-sweep.sh --selftest || return $?
  run_rung 'campaign classifier selftest' "$patina_cli" patina campaign --selftest || return $?

  run_rung 'native ecosystem receipt selftest' scripts/check-native-testbeds.sh --selftest || return $?

  start_rung 'cross-target smoke' "${testbed_env[@]}" scripts/smoke-cross-target.sh
  start_rung 'WASI validation' "${testbed_env[@]}" scripts/validate-wasi.sh
  wait_rungs || return $?
}

case $profile in
  selftest) run_rung 'output contract selftest' output_selftest ;;
  full)
    export PATINA_REQUIRE_HOST_ORACLE="${PATINA_REQUIRE_HOST_ORACLE:-1}"
    run_full
    ;;
  fast) run_fast ;;
esac
