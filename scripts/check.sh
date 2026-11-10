#!/usr/bin/env bash
# Everything this host can check (`mise run check:full`): the lints, the suite
# and the testbeds. CI is the landing gate; run this when a change is broad and
# you want the answer before pushing. A passing step is silent, a failed one
# prints its log, and every log stays in the directory the last line names.
set -uo pipefail
cd "$(dirname "$0")/.."

# Every guest a step builds shares the native shim builds of the workspace's
# target dir, whatever target dir the guest itself builds in.
export PATINA_SHIM_TARGET_DIR="$PWD/target"
logs=$(mktemp -d "${TMPDIR:-/tmp}/patina-check.XXXXXX") || exit 1
start=$(date +%s)
trap 'status=$?; kill $(jobs -p) 2>/dev/null; echo "$([[ $status == 0 ]] && echo PASS || echo FAIL) ($(( $(date +%s) - start ))s); logs: $logs"' EXIT

# step NAME COMMAND...: run one check with its output in $logs/NAME.log.
step() {
  local name=$1
  shift
  "$@" >"$logs/$name.log" 2>&1 && return
  echo "FAIL $name: $*"
  cat "$logs/$name.log"
  return 1
}

# The other OS family and, on Linux, the other Linux architecture: their cfgs,
# constants and syscall tables otherwise compile only in CI.
case "$(uname -s)/$(uname -m)" in
  Darwin/*) cross=(x86_64-unknown-linux-gnu) ;;
  Linux/aarch64) cross=(aarch64-apple-darwin x86_64-unknown-linux-gnu) ;;
  *) cross=(aarch64-apple-darwin aarch64-unknown-linux-gnu) ;;
esac

step format cargo fmt --all -- --check || exit
step structure scripts/check-structure.sh || exit
step clippy cargo clippy --workspace --all-targets --locked -- -D warnings || exit
for target in "${cross[@]}"; do
  step "clippy-$target" cargo clippy --workspace --all-targets --locked --target "$target" -- -D warnings || exit
done
step macros cargo test --quiet -p patina-dst --features macros --locked || exit
# One build of the workspace suite; its cargo-patina drives every testbed.
step build cargo nextest run --profile local --workspace --locked --no-run || exit
export PATINA_CLI="$PWD/target/debug/cargo-patina"

# The suite leaves cores idle and a testbed is mostly one guest run after
# another, so they overlap: the suite and the doctests in the workspace's
# target dir, each testbed script in one of its own.
scripts=(scripts/smoke-native.sh testbeds/{fifo-ipc,python-guest,python-sdk,workq,pubsub}/run-patina.sh
  testbeds/patina-macro-adopter/run.sh)
# The syscall-user-dispatch testbeds, and Go, whose runtime issues raw syscalls.
[[ $(uname -s)/$(uname -m) == Linux/x86_64 ]] &&
  scripts+=(testbeds/{rustix-default,cap-std-dirfd,go-guest,go-sdk}/run-patina.sh)
names=(tests doctests)
pids=()
# One test process per two cores unless NEXTEST_TEST_THREADS says otherwise: a
# test can start guest builds of its own.
step tests cargo nextest run --profile local --workspace --locked \
  --test-threads "${NEXTEST_TEST_THREADS:-$(( ($(getconf _NPROCESSORS_ONLN) + 1) / 2 ))}" &
pids+=($!)
step doctests cargo test --quiet --doc --workspace --locked &
pids+=($!)
for script in "${scripts[@]}"; do
  name=${script%/run*.sh}
  name=$(basename "$name" .sh)
  names+=("$name")
  CARGO_TARGET_DIR="$PWD/target/check/$name" step "$name" "$script" &
  pids+=($!)
done
failed=()
for i in "${!pids[@]}"; do
  wait "${pids[$i]}" || failed+=("${names[$i]}")
done
[[ ${#failed[@]} == 0 ]] || { echo "failed: ${failed[*]}"; exit 1; }
