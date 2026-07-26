#!/usr/bin/env bash
###############################################################################
# UNTESTED SKETCH -- do not expect this to run yet.
#
# This is the intended shape of the LATER Patina phase, written from the
# `cargo patina` CLI (see crates/cargo-patina/src/lib.rs). It has NOT been
# executed: this change is native-only. Treat every command below as a
# proposal to be validated when the Patina phase actually lands.
#
# THE SWAP IS EXACTLY THE RUNNER. The harness binary is 100% std-pure -- no
# Patina imports, no cfg(patina). The harness args are byte-for-byte identical
# to run-native.sh; only the leading command changes:
#
#   native :  cargo run --release        -- <harness args>
#   patina :  cargo patina run --release -- <harness args>
#
# The SAME binary becomes deterministic under Patina because `cargo patina run`
# builds it with cfg(patina)/cfg(dst) and executes it under the deterministic
# runtime, which interposes std::thread (deterministic scheduler), std::net
# UDP/TCP (SimNet over loopback), and std::time (sleep advances virtual time).
# Our 100ms tick loop, the UDP transport, and the file writes all pass through
# those boundaries. Fault topology (drop/reorder/partition/crash) comes from
# Patina's experiment plane and the seed -- NOT from any code in this harness.
###############################################################################
set -euo pipefail

# `cargo patina run` forwards to `cargo run`, so invoke it from the harness
# package. (Cross-workspace wiring of the patina-native-shim staticlib, which
# lives in the root workspace, is a phase-time detail to validate.)
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

data_dir="$here/target/patina-data"

# ---------------------------------------------------------------------------
# 1. Single deterministic run at a fixed seed. Note the harness args after `--`
#    are identical to run-native.sh's healthy scenario. The Patina --seed
#    (before `--`) selects the deterministic world; the harness's own --seed
#    (after `--`) selects client payloads, exactly as in the native run.
# ---------------------------------------------------------------------------
cargo patina run --release --seed 42 -- \
  --seed 1 --proposals 50 --base-port 4001 --data-dir "$data_dir"

# ---------------------------------------------------------------------------
# 2. Seed sweep: explore many interleavings of scheduler + SimNet drop/reorder,
#    each a fully independent deterministic world. `explore` re-runs the same
#    cargo command across a range of root seeds.
# ---------------------------------------------------------------------------
cargo patina explore run --seeds 64 --start 0 --release -- \
  --seed 1 --proposals 50 --base-port 4001 --data-dir "$data_dir"

# ---------------------------------------------------------------------------
# 3. Record a failing seed, then shrink it. `--record` captures the boundary
#    trace; `minimize` delta-debugs it against an oracle that replays the trace
#    and exits non-zero while the failure still reproduces.
# ---------------------------------------------------------------------------
# cargo patina run --release --seed 1234 --record fail.trace -- \
#   --proposals 50 --base-port 4001 --data-dir "$data_dir"
# cargo patina minimize fail.trace --output fail.min.trace -- \
#   cargo patina run --release --replay '$PATINA_MINIMIZE_TRACE' -- \
#     --proposals 50 --base-port 4001 --data-dir "$data_dir"

# ---------------------------------------------------------------------------
# 4. Fault surfaces the Patina phase drives WITHOUT touching this harness:
#      - message loss / reorder / partition via SimNet on the UDP transport;
#      - crash-restart by faulting the FileStorage fsync points, then letting
#        the node re-open from whatever bytes survived (FileStorage::open);
#      - added latency via Patina's net-latency knob.
#    All of these are experiment-plane inputs, not harness code.
# ---------------------------------------------------------------------------
echo "UNTESTED SKETCH complete -- validate each step when the Patina phase lands."
