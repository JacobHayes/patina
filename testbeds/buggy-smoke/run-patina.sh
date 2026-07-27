#!/usr/bin/env bash
###############################################################################
# Patina phase for the buggy-smoke canary -- TESTED end-to-end (macOS/arm64,
# 2026-07-26). See PATINA-RESULTS.md for the full write-up, hashes, and the
# root-cause analysis behind every KNOWN-GAP below.
#
# THE SWAP IS EXACTLY THE RUNNER. buggy-smoke is 100% std-pure (no Patina
# imports, no cfg(patina)). Under Patina the SAME source is built with
# cfg(patina)/cfg(dst) and the interposing native shim via `cargo patina
# native-build`, then executed under the deterministic runtime via `cargo patina
# native-run`. The binary args after `--` are byte-for-byte identical to
# run-native.sh; only the runner changes:
#
#   native :  target/release/buggy-smoke                       --bug X ...
#   patina :  cargo patina run buggy-smoke.patina --seed S -- --bug X ...
#
# This script encodes the OBSERVED Patina behavior as assertions and exits
# nonzero if any currently-passing expectation regresses. Two modes are known
# gaps (deadlock, udp-order); they are probed as INFORMATIONAL and do not fail
# the run, but the script flags loudly if their status changes so the gap notes
# in PATINA-RESULTS.md can be updated when the underlying Patina work lands.
###############################################################################
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"          # Patina workspace root
cd "$here"

work="$(mktemp -d "${TMPDIR:-/tmp}/buggy-smoke-patina.XXXXXX")"
trap 'rm -rf "$work"' EXIT
PBIN="$work/buggy-smoke.patina"

# Word-split intentionally so the runner can carry flags.
CARGO="${CARGO:-cargo}"

echo "==> building cargo-patina (release) and the instrumented guest binary"
# native-build must run from within the Patina workspace: it compiles the
# patina-native-shim staticlib from the surrounding crates and links it below
# the guest. Reuse an existing release cargo-patina if present.
PATINA_BIN="$root/target/release/cargo-patina"
if [[ ! -x "$PATINA_BIN" ]]; then
  ( cd "$root" && $CARGO build --release -p cargo-patina )
fi
( cd "$root" && "$PATINA_BIN" patina build "$here" --output "$PBIN" --release >/dev/null )
echo "    guest: $PBIN"

fail=0
# ALLOWANCE-FREE: task #10 known-safe-listed __NSGetArgc/__NSGetArgv and now
# interposes _confstr/temp_dir, so this std-pure guest passes the pre-run audit
# with zero --allow-unsupported-symbols. Determinism here is unqualified.
patina() { "$PATINA_BIN" patina run "$PBIN" "$@"; }
# `replay <trace> [flags]` reproduces a recorded run flag-free: the seed and the
# guest arguments are restored from the trace, so no `--` section is re-passed.
replay() { "$PATINA_BIN" patina replay "$PBIN" "$@"; }

# ---------------------------------------------------------------------------
# clean_det <name> [args...]
#   Assert the mode runs CLEAN (exit 0, "CLEAN bug=<name>") under Patina at
#   seed 1 AND is byte-identical across 3 recorded repeats (trace + stdout).
# ---------------------------------------------------------------------------
clean_det() {
  local name="$1"; shift
  local h0="" o0="" i tf out rc h
  for i in 1 2 3; do
    tf="$work/${name}_${i}.patina"
    set +e
    out="$(patina --record "$tf" --seed 1 -- --bug "$name" "$@" 2>/dev/null)"; rc=$?
    set -e
    h="$(shasum -a 256 "$tf" | awk '{print $1}')"
    if [[ $i -eq 1 ]]; then h0="$h"; o0="$out|rc=$rc"; fi
    if [[ "$h" != "$h0" ]]; then echo "FAIL ($name): trace repeat $i differs ($h != $h0)"; fail=1; return; fi
    if [[ "$out|rc=$rc" != "$o0" ]]; then echo "FAIL ($name): output repeat $i differs"; fail=1; return; fi
  done
  if [[ "$o0" != "CLEAN bug=$name|rc=0" ]]; then
    echo "FAIL ($name): expected CLEAN/exit0 under Patina, got: $o0"; fail=1; return
  fi
  echo "OK   ($name): CLEAN + byte-identical across 3 repeats (trace ${h0:0:12}..)"
}

echo "==> modes that run cleanly + deterministically under Patina (seed 1)"
clean_det no-fsync       --iters 32
clean_det tight-deadline --iters 10
clean_det lost-update    --iters 100
clean_det unlucky-byte

echo "==> unlucky-byte: seeded-entropy sweep must find a tripping seed (derived=0x00)"
# Patina's SeededEntropy interposes std RandomState; each root seed yields a
# deterministic 16-byte draw, so a bounded sweep hits the 1-in-256 fold to 0x00.
hit=""
for s in $(seq 0 300); do
  set +e; out="$(patina --seed "$s" -- --bug unlucky-byte 2>/dev/null)"; rc=$?; set -e
  if [[ $rc -ne 0 ]]; then hit="$s"; hit_out="$out"; break; fi
done
if [[ -n "$hit" && "$hit_out" == "BUG_CAUGHT bug=unlucky-byte detail=derived=0x00 stored=0" ]]; then
  echo "OK   (unlucky-byte sweep): first trip at seed=$hit :: $hit_out"
else
  echo "FAIL (unlucky-byte sweep): no derived=0x00 trip within seeds 0..300"; fail=1
fi

echo "==> replay: a recorded trip must replay to the identical outcome"
if [[ -n "$hit" ]]; then
  rec="$work/ub_trip.patina"
  rec_out="$(patina --record "$rec" --seed "$hit" -- --bug unlucky-byte 2>/dev/null || true)"
  # Flag-free replay: the guest arguments are restored from the trace metadata.
  rep_out="$(replay "$rec" 2>/dev/null || true)"
  if [[ "$rec_out" == "$rep_out" && "$rep_out" == BUG_CAUGHT* ]]; then
    echo "OK   (replay): record==replay :: $rep_out"
  else
    echo "FAIL (replay): record='$rec_out' replay='$rep_out'"; fail=1
  fi
  # Strict-replay must REJECT a `--` section that does not match the recorded
  # guest arguments -- now an UP-FRONT (parse-time) error naming both argv lists,
  # not a mid-run divergence.
  set +e
  mism="$(replay "$rec" -- --bug lost-update --iters 100 2>&1 >/dev/null)"; mrc=$?
  set -e
  if [[ $mrc -ne 0 && "$mism" == *"guest-argument mismatch"* ]]; then
    echo "OK   (replay strictness): wrong-args replay rejected up front (exit $mrc)"
  else
    echo "FAIL (replay strictness): wrong-args replay was not rejected (exit=$mrc): $mism"; fail=1
  fi
fi

# ---------------------------------------------------------------------------
# STATUS PROBES -- informational, do NOT fail the run. If an observed status
# changes (a Patina fix lands or regresses), the script shouts so these notes and
# PATINA-RESULTS.md get updated. The bug-FINDING gate lives in find-bugs.sh; this
# is just the "what still works / what's still blocked" pulse. See
# PATINA-RESULTS.md for the per-bug detail.
# ---------------------------------------------------------------------------
echo "==> status probes (informational)"

# deadlock: CAUGHT since task #10 (Parker interpose). The mpmc recv_timeout now
# parks with a virtual timer; all-parked -> the runtime's deadlock rescue advances
# the clock to the deadline -> watchdog-timeout. Expect BUG_CAUGHT (no more hang).
set +e
dout="$(timeout 30 "$PATINA_BIN" patina run "$PBIN" --seed 1 -- --bug deadlock --iters 64 2>/dev/null)"; drc=$?
set -e
if [[ "$dout" == *"BUG_CAUGHT bug=deadlock detail=watchdog-timeout"* ]]; then
  echo "OK   (deadlock): CAUGHT watchdog-timeout (task #10 Parker fix) -- EXPECTED"
elif [[ $drc -eq 124 ]]; then
  echo "REGRESSED (deadlock): hangs again -- task #10 Parker interpose broke"; fail=1
else
  echo "CHANGED (deadlock): $dout (exit=$drc) -- update notes"
fi

# udp-order: task #11 landed deterministic SO_RCVTIMEO, so the PLAIN run (no
# reorder fault) now succeeds and stays CLEAN (loopback SimNet is in-order). The
# bug is CAUGHT under --net-jitter-nanos in find-bugs.sh. Here we just assert the
# plain baseline is CLEAN (set_read_timeout no longer fail-closes).
set +e
uout="$(patina --seed 1 -- --bug udp-order --iters 64 2>/dev/null)"; urc=$?
set -e
if [[ "$uout" == "CLEAN bug=udp-order" ]]; then
  echo "OK   (udp-order): plain run CLEAN (SO_RCVTIMEO landed); bug caught via --net-jitter in find-bugs.sh"
elif [[ "$uout" == *"timeout-setup-failed"* ]]; then
  echo "REGRESSED (udp-order): set_read_timeout fail-closed again (SO_RCVTIMEO)"; fail=1
else
  echo "CHANGED (udp-order): $uout (exit=$urc) -- re-run find-bugs.sh"
fi

echo
if [[ $fail -eq 0 ]]; then
  echo "ALL PATINA REGRESSION CHECKS PASSED (bug-finding gate: run find-bugs.sh -- 6/6)"
else
  echo "PATINA CHECKS FAILED"
fi
exit $fail
