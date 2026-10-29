#!/usr/bin/env bash
###############################################################################
# workq under Patina: the self-checking regression gate. Exits nonzero on any
# regression:
#   [1] a short `cargo patina campaign` over campaign.json: guest-drawn workload
#       sizes, net/sleep/buggify/swarm faults, a process or machine crash and
#       restart at a drawn per-operation rate, and an in-process server restart
#       per generation, with the campaign's own re-run check. Every generation
#       must be clean;
#   [2] the in-process fail-closed-recovery self-test (mid-log corruption
#       aborts, a torn tail truncates);
#   [3] each planted `--bug` is caught within a bounded seed window (a bug no
#       seed catches fails the leg), and the catching run strict-replays with
#       an identical verdict stream and trace. `skip-wal-fsync` is caught only
#       by a machine crash: the same run under a process crash, whose page
#       cache survives, must pass.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/workq}"
export CARGO_TARGET_DIR="$target_dir"
built="$target_dir/patina/workq"
PATINA="${PATINA_CLI:-$target_dir/release/cargo-patina}"
GENS="${WORKQ_CAMPAIGN_GENS:-24}"

cd "$repo_root"
if [[ -z ${PATINA_CLI:-} ]] && ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if [[ ! -x $PATINA ]]; then
  echo "FATAL: $PATINA is not an executable cargo-patina" >&2; exit 3
fi
if ! mkdir -p "$target_dir/patina"; then
  echo "FATAL: mkdir $target_dir/patina failed" >&2; exit 3
fi
if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then
  echo "FATAL: patina build of the workq harness failed" >&2; exit 3
fi

work="$(mktemp -d)"
trap 'printf "Logs: %s\n" "$work"' EXIT
fail=0
start_secs=$SECONDS
run() { "$PATINA" patina run "$built" "$@"; }
replay() { "$PATINA" patina replay "$built" "$@"; }
stderr_tail() { [[ -s "$1" ]] && sed -n '1,20p' "$1" | sed 's/^/      stderr| /'; }

echo "==> [1] campaign: $GENS generations of campaign.json"
if ! "$PATINA" patina campaign "$built" --spec "$here/campaign.json" --gens "$GENS" \
    --out-dir "$work/campaign" >"$work/campaign.out" 2>&1; then
  echo "    FAIL: the campaign found something"; fail=1
  grep -A3 -- '-- failure signatures --' "$work/campaign.out" | sed 's/^/      /'
fi

echo "==> [2] fail-closed recovery self-test"
if ! out="$(run -- --check-recovery-fail-closed 2>"$work/self.err")" \
    || ! grep -q 'WORKQ_RECOVERY_SELFTEST ok' <<<"$out"; then
  echo "    FAIL: recovery self-test did not pass"; fail=1; stderr_tail "$work/self.err"
fi

# The bugs run on a fixed small workload so the pinned seed windows stay valid.
ARGS=(--seed 7 --jobs 24 --workers 3 --producers 2 --base-port 5001 --data-dir /workq --timeout-secs 90)
BUG_SEED_WINDOW=8
bug_leg() {
  local name="$1" first="$2" pknobs="$3" gargs="$4" marker="$5"
  local tr="$work/bug.$name.trace" err="$work/bug.$name.err" bseed caught=0
  echo "==> [3] planted bug $name"
  for bseed in $(seq "$first" $((first + BUG_SEED_WINDOW - 1))); do
    if ! run --seed "$bseed" $pknobs --record "$tr" -- "${ARGS[@]}" $gargs >/dev/null 2>"$err" \
        && grep -Eq "$marker" "$err"; then caught=1; break; fi
  done
  bseed_caught=""
  if [[ $caught -ne 1 ]]; then
    echo "    FAIL: not caught by seeds $first..$((first + BUG_SEED_WINDOW - 1)) (expected '$marker')"
    fail=1; stderr_tail "$err"; return
  fi
  local th rerr
  th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
  rerr="$work/bug.$name.replay.err"
  replay "$tr" >/dev/null 2>"$rerr" || true
  if [[ "$(grep '^PATINA_VERDICT ' "$rerr")" != "$(grep '^PATINA_VERDICT ' "$err")" \
      || "$th" != "$(shasum -a256 "$tr" | cut -d' ' -f1)" ]] || ! grep -Eq "$marker" "$rerr"; then
    echo "    FAIL: the replay did not reproduce the verdict stream and trace"; fail=1
  fi
  bseed_caught="$bseed"
}
bug_leg dedup-ignore-producer 1 "" "--timeout-secs 20 --bug dedup-ignore-producer" '^WORKQ_FAILURE not-converged'
bug_leg skip-redelivery-commit 2 "--buggify=500 --buggify-after-setup" "--bug skip-redelivery-commit" '^PATINA_VERDICT .*kind=violation '
bug_leg apply-check-outside-lock 1 "--buggify=500 --buggify-after-setup" "--tick-ms 2 --bug apply-check-outside-lock" '^PATINA_VERDICT .*kind=violation '
bug_leg ignore-short-write 1 "--fs-short-permille 200" "--bug ignore-short-write" '^PATINA_VERDICT .*kind=violation '
fsync_bug="--ack-ledger /workq-acks --bug skip-wal-fsync"
bug_leg skip-wal-fsync 2 "--crash-permille 10 --crash-kind machine" "$fsync_bug" '^PATINA_VERDICT .*kind=violation '
echo "==> [3] skip-wal-fsync survives a process crash"
if [[ -n ${bseed_caught:-} ]] && ! run --seed "$bseed_caught" --crash-permille 10 --crash-kind process \
    -- "${ARGS[@]}" $fsync_bug >/dev/null 2>"$work/bug.skip-wal-fsync.process.err"; then
  echo "    FAIL: a process crash lost an unsynced record (seed $bseed_caught)"; fail=1
  stderr_tail "$work/bug.skip-wal-fsync.process.err"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "==> FAILED"; exit 1
fi
echo "workq: PASS ($(( SECONDS - start_secs ))s)"
