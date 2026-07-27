#!/usr/bin/env bash
###############################################################################
# RUNG-1 GATE: does Patina FIND all six planted bugs?
#
# Passes only when Patina produces a deterministic failing run (a BUG_CAUGHT
# contract line + nonzero exit) for every --bug mode. Prints a CAUGHT/BLOCKED
# scorecard with the catching seed and a reproduced trace hash per catch, and
# exits 0 iff all six are caught. (Contrast run-patina.sh, which checks the
# already-working clean+determinism+replay behavior on the PLAIN build and also
# demonstrates the vacuous-schedule diagnostic.)
#
# A "catch" REQUIRES the BUG_CAUGHT line -- a bare nonzero exit does NOT count.
#
# ALLOWANCE-FREE: zero --allow-unsupported-symbols (task #10 known-safe-listed
# __NSGetArgc/__NSGetArgv and interposes _confstr/temp_dir).
#
# SINGLE --yield-points BUILD for all six (simplest wiring; verified by task #12).
# The basic-block yield points (LLVM SanitizerCoverage, stable -C flags, no
# RUSTC_BOOTSTRAP) make lost-update's atomics-only RMW race schedulable while the
# other five still catch. The instrumentation reshapes the schedule space, so
# CATCHING SEEDS DIFFER from the plain build (e.g. deadlock catches at seed 0
# here, not seed 1) -- so we SWEEP for each bug's first catching seed rather than
# hardcode, which keeps the gate robust to schedule shifts. The build carries a
# `+yieldpoints` trace fingerprint suffix, so its traces never cross-replay
# against a plain binary (fails closed by design).
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/buggy-smoke-findbugs.XXXXXX")"
trap 'rm -rf "$work"' EXIT
BIN="$work/yield.patina"

PATINA_BIN="$root/target/release/cargo-patina"
[[ -x "$PATINA_BIN" ]] || ( cd "$root" && cargo build --release -p cargo-patina >/dev/null )
( cd "$root" && "$PATINA_BIN" patina build "$here" --output "$BIN" --release --yield-points \
    2>&1 | grep -a "PATINA_NATIVE_BUILD_YIELD_POINTS" || true )

caught=0
declare -a SCORE
contract() { grep -aE '^(CLEAN|BUG_CAUGHT)' <<<"$1" | head -1; }

# find_bug <name> <ok-substring> <max-seed> <native-flags...> -- <guest args...>
#   Sweep seeds 0..max for the first BUG_CAUGHT whose detail contains the
#   substring, then record that seed's trace and score it.
find_bug() {
  local nm="$1" oksub="$2" maxseed="$3"; shift 3
  local flags=() guest=() seen=0
  for a in "$@"; do
    if [[ $seen -eq 0 && "$a" == "--" ]]; then seen=1; continue; fi
    if [[ $seen -eq 0 ]]; then flags+=("$a"); else guest+=("$a"); fi
  done
  local s line
  for s in $(seq 0 "$maxseed"); do
    line="$(contract "$(timeout 40 "$PATINA_BIN" patina run "$BIN" "${flags[@]}" --seed "$s" -- "${guest[@]}" 2>/dev/null)")"
    if [[ "$line" == *"$oksub"* && "$line" == BUG_CAUGHT* ]]; then
      local tf="$work/${nm}.patina"
      "$PATINA_BIN" patina run "$BIN" "${flags[@]}" --record "$tf" --seed "$s" -- "${guest[@]}" >/dev/null 2>&1
      local h; h="$(shasum -a 256 "$tf" 2>/dev/null | awk '{print $1}')"
      caught=$((caught+1))
      SCORE+=("CAUGHT  $nm  (seed=$s) :: $line  trace=${h:0:16}..")
      echo "CAUGHT  $nm  seed=$s  $line"
      echo "        repro: cargo patina run <yield.patina> ${flags[*]} --seed $s -- ${guest[*]}"
      return
    fi
  done
  SCORE+=("BLOCKED $nm :: no catch in seeds 0..$maxseed")
  echo "BLOCKED $nm :: no catch in seeds 0..$maxseed"
}

echo "=== unlucky-byte (seeded entropy) ==="
find_bug unlucky-byte   "derived=0x00"          300 -- --bug unlucky-byte
echo "=== deadlock (scheduler + virtual-clock rescue) ==="
find_bug deadlock       "watchdog-timeout"       40 -- --bug deadlock --iters 64
echo "=== no-fsync (CrashFs durability) ==="
find_bug no-fsync       "lost-durable-records"   40 --fs-crash-at close:1 -- --bug no-fsync --iters 32
echo "=== tight-deadline (clock latency) ==="
find_bug tight-deadline "elapsed-ms="            40 --sleep-jitter-nanos 8000000..12000000 -- --bug tight-deadline --iters 10
echo "=== udp-order (SimNet reorder + deterministic recv timeout) ==="
find_bug udp-order      "out-of-order"           40 --net-jitter-nanos 0..1000000 -- --bug udp-order --iters 64
echo "=== lost-update (yield-points makes the atomics-only RMW race schedulable) ==="
find_bug lost-update    "lost="                  40 -- --bug lost-update --iters 2

echo
echo "================ RUNG-1 BUG-FINDING SCORECARD ================"
printf '%s\n' "${SCORE[@]}"
echo "============================================================="
echo "CAUGHT $caught / 6"
if [[ $caught -eq 6 ]]; then
  echo "RUNG 1 GATE: PASS -- Patina finds all six planted bugs (single yield-points build, allowance-free)."
  exit 0
else
  echo "RUNG 1 GATE: NOT YET -- $((6-caught)) bug(s) still not caught (see BLOCKED above)."
  exit 1
fi
