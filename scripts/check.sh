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

usage() {
  cat <<'EOF'
Usage: scripts/check.sh <full|fast|msrv>

  full  Full local pre-landing gate. Cheap checks run first, the e2e-heavy
        workspace test rung runs alone, then independent runtime/testbed gates
        run concurrently.
  fast  Inner-loop gate; excludes only the cargo-patina end_to_end test binary
        and the landing-only docs/packaging/native-shim/testbed/full-e2e rungs.
  msrv  Execute the complete Rust 1.86 suite. This is CI/final-gate evidence,
        not part of the ordinary local landing gate.

Successful rung logs are hidden. On failure, the complete rung log and exact
command are printed. The runner uses one Cargo target dir for serial work and one
under target/check/parallel/ for each parallel rung. PATINA_CHECK_JOBS is
intentionally not exposed: the full profile uses bounded, reviewed concurrency
groups whose members have independent scratch/output paths.
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

rung_slug() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-//; s/-$//'
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
  local arg command target_dir
  target_dir="$check_target_base/parallel/$(rung_slug "$label")"
  printf -v command 'CARGO_TARGET_DIR=%q' "$target_dir"
  for arg in "$@"; do
    printf -v command '%s %q' "$command" "$arg"
  done
  printf 'START %s [parallel]\n' "$label"
  labels+=("$label")
  commands+=("$command")
  log_paths+=("$log")
  status_paths+=("$status_file")
  start_times+=("$(date +%s)")
  (
    CARGO_TARGET_DIR="$target_dir" "$@" >"$log" 2>&1
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

run_fast_workspace_tests() {
  # cargo has no "all tests except this integration-test binary" selector, so
  # run every other package normally, then enumerate cargo-patina's non-e2e
  # targets. This is the measured fix for the old fast tier's 190s+ e2e binary.
  local cargo_patina_targets=(--lib --bin cargo-patina)
  local test_path test_name
  while IFS= read -r test_path; do
    test_name=$(basename "${test_path%.rs}")
    cargo_patina_targets+=(--test "$test_name")
  done < <(find crates/cargo-patina/tests -maxdepth 1 -type f -name '*.rs' ! -name end_to_end.rs | LC_ALL=C sort)

  cargo test --workspace --exclude cargo-patina --locked &&
    cargo test -p cargo-patina --locked "${cargo_patina_targets[@]}" &&
    cargo test -p cargo-patina --locked --doc
}

run_msrv_check() {
  cargo +1.86.0 check --workspace --all-targets --locked --target-dir "$check_target_base/msrv-check"
}

run_msrv_detector() {
  cargo +1.86.0 test --target-dir "$check_target_base/msrv-check" -p cargo-patina \
    --test self_sufficient_binary --locked
}

run_msrv_macro_feature_test() {
  cargo +1.86.0 test --target-dir "$check_target_base/msrv-check" -p patina-dst \
    --features macros --locked
}

run_msrv_full() {
  # Keep MSRV artifacts separate from the stable serial and parallel target dirs.
  # cargo-patina's internal shim cache independently keys itself by the complete
  # toolchain.
  local msrv_target="$check_target_base/msrv"
  cargo +1.86.0 test --target-dir "$msrv_target" --workspace --locked &&
    cargo +1.86.0 test --target-dir "$msrv_target" -p patina-dst --features macros --locked
}

run_full() {
  local total_start
  total_start=$(date +%s)
  printf 'TARGET_BASE %s\n' "$check_target_base"

  # Cheap, high-signal failures stay serial and stop before expensive work.
  run_rung 'format' cargo fmt --all -- --check || return $?
  run_rung 'host clippy' cargo clippy --workspace --all-targets --locked -- -D warnings || return $?
  run_rung 'Linux-cfg clippy' cargo clippy --workspace --all-targets --locked --target x86_64-unknown-linux-gnu -- -D warnings || return $?
  run_rung 'documentation' cargo doc --workspace --no-deps --locked || return $?
  run_rung 'CLI flag drift' scripts/check-flag-drift.sh || return $?
  # Every workspace member packages cleanly (manifest metadata, readme paths,
  # include/exclude). --no-verify skips the per-crate verify build; the release
  # dry run (scripts/publish.sh) covers that and the license-text audit.
  run_rung 'crate packaging' cargo package --workspace --no-verify --locked --allow-dirty || return $?
  run_rung 'workq classifier selftest' testbeds/workq/fuzz-sweep.sh --selftest || return $?
  run_rung 'campaign classifier selftest' cargo run -q -p cargo-patina -- patina campaign --selftest || return $?
  run_rung 'conformance gate selftest' testbeds/syscall-conformance/gate.sh --selftest || return $?
  run_rung 'MSRV cargo check' run_msrv_check || return $?
  run_rung 'MSRV rodata detector' run_msrv_detector || return $?
  run_rung 'MSRV macro feature test' run_msrv_macro_feature_test || return $?

  # The cargo-patina end_to_end binary dominates the stable workspace suite and
  # contends badly with other CPU-heavy cargo/check rungs, so the full workspace
  # test rung runs alone. The post-test group below gets one Cargo target dir per
  # rung through start_rung, plus each script's own runtime scratch paths.
  run_rung 'stable workspace tests (includes e2e)' cargo test --workspace --locked || return $?

  start_rung 'native-shim validation' scripts/validate-native-shim.sh
  start_rung 'macro adopter testbed' testbeds/patina-macro-adopter/run.sh
  start_rung 'pubsub testbed' testbeds/pubsub/run-patina.sh
  start_rung 'workq testbed' testbeds/workq/run-patina.sh
  start_rung 'WASI validation' scripts/validate-wasi.sh
  start_rung 'cross-target smoke' scripts/smoke-cross-target.sh
  # The syscall-conformance testbed's full tier: every probe through all three
  # vehicles natively (host oracle) and under patina, plus record/replay identity
  # and the strace leak leg. Linux-only; loud counted skip elsewhere. (A frozen
  # family's own gate, `gate.sh --family <f>`, is its builder's done-line; it
  # joins this ladder in the change that makes it pass.)
  start_rung 'syscall conformance' testbeds/syscall-conformance/run.sh
  wait_rungs || return $?

  printf 'PASS  full landing gate (%ss total)\n' "$(( $(date +%s) - total_start ))"
}

run_fast() {
  local total_start
  total_start=$(date +%s)
  printf 'TARGET_BASE %s\n' "$check_target_base"
  run_rung 'format' cargo fmt --all -- --check || return $?
  run_rung 'host clippy' cargo clippy --workspace --all-targets --locked -- -D warnings || return $?
  run_rung 'Linux-cfg clippy' cargo clippy --workspace --all-targets --locked --target x86_64-unknown-linux-gnu -- -D warnings || return $?

  # The fast test rung is cargo-heavy enough to inflate every other cargo-using
  # smoke when overlapped, even though it no longer contains the e2e binary.
  # Run it alone, then group the short independent smoke/selftest rungs.
  run_rung 'workspace tests (no cargo-patina e2e)' run_fast_workspace_tests || return $?
  run_rung 'CLI flag drift' scripts/check-flag-drift.sh || return $?
  run_rung 'MSRV cargo check' run_msrv_check || return $?
  run_rung 'workq classifier selftest' testbeds/workq/fuzz-sweep.sh --selftest || return $?
  run_rung 'campaign classifier selftest' cargo run -q -p cargo-patina -- patina campaign --selftest || return $?
  run_rung 'conformance gate selftest' testbeds/syscall-conformance/gate.sh --selftest || return $?

  start_rung 'syscall conformance (fast tier)' testbeds/syscall-conformance/run.sh --fast
  start_rung 'WASI validation' scripts/validate-wasi.sh
  start_rung 'cross-target smoke' scripts/smoke-cross-target.sh
  wait_rungs || return $?

  printf 'PASS  fast check (%ss total)\n' "$(( $(date +%s) - total_start ))"
}

case $profile in
  full) run_full ;;
  fast) run_fast ;;
  msrv) run_rung 'MSRV full compatibility suite' run_msrv_full ;;
esac
