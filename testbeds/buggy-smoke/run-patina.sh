#!/usr/bin/env bash
###############################################################################
# UNTESTED SKETCH -- do not expect this to run yet.
#
# This is the intended shape of the LATER Patina phase, written from the
# `cargo patina` CLI (crates/cargo-patina/src/lib.rs). It has NOT been executed:
# this change is native-only. Treat every command below as a proposal to be
# validated when the Patina phase actually lands.
#
# THE SWAP IS EXACTLY THE RUNNER. The binary is 100% std-pure -- no Patina
# imports, no cfg(patina). The binary args after `--` are identical to
# run-native.sh; only the leading command changes:
#
#   native :  cargo run --release        -- --bug X ...
#   patina :  cargo patina run --release -- --bug X ...
#
# The SAME binary becomes deterministic under Patina because `cargo patina run`
# builds it with cfg(patina)/cfg(dst) and runs it under the deterministic
# runtime, which interposes std::thread (DetScheduler), std::net UDP (SimNet),
# std::time (virtual clock), std::fs (Mem/CrashFs), and std entropy (SeededEntropy).
#
# CONFIDENCE VARIES BY BUG (see README + the concerns block at the bottom). The
# scheduler and seeded-entropy bugs map cleanly onto `explore`; the fault-
# injection bugs (crash, clock latency, packet reorder/drop) likely need topology
# that a std-pure binary cannot request through the current native CLI, and may
# require per-driver knobs or an explicit-Context harness to trigger.
###############################################################################
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# ---------------------------------------------------------------------------
# 1. lost-update -- deterministic scheduler (HIGH confidence).
#    `explore` runs the same seeded scenario across many root seeds; the
#    DetScheduler drives thread interleavings, so the read-then-write drop that
#    is racy natively becomes reproducible on the seeds that schedule it.
# ---------------------------------------------------------------------------
cargo patina explore run --release --seeds 200 -- --bug lost-update --iters 100

# ---------------------------------------------------------------------------
# 2. deadlock -- deterministic scheduler + deadlock detection (MEDIUM-HIGH).
#    The AB/BA inversion needs worker A to hold `a` while worker B takes `b`.
#    The scheduler can construct that interleaving; DetScheduler reports an
#    explicit deadlock outcome (patina-sched-det has a deadlock state), and the
#    binary's own watchdog is the backstop. Widen the search if a single sweep
#    misses the exact alignment.
# ---------------------------------------------------------------------------
cargo patina explore run --release --seeds 500 -- --bug deadlock --iters 64
# To shrink a found schedule to the minimal interleaving, record then minimize:
#   cargo patina run --release --seed <HIT> --record deadlock.patina -- --bug deadlock --iters 64
#   cargo patina minimize deadlock.patina --output deadlock.min.patina -- \
#       target/release/buggy-smoke --bug deadlock --iters 64

# ---------------------------------------------------------------------------
# 3. unlucky-byte -- seeded entropy sweep (HIGH confidence).
#    NOTE: pass NO app `--seed`, so the binary draws from std RandomState, which
#    Patina's SeededEntropy interposes. Each Patina root seed then yields a
#    different 16-byte draw, so the sweep finds the 1-in-256 unlucky draw fast.
# ---------------------------------------------------------------------------
cargo patina explore run --release --seeds 300 -- --bug unlucky-byte
# Canonicalize the triggering seed once found:
#   cargo patina minimize --scenario --seed <HIT> --seed-budget 300 -- \
#       target/release/buggy-smoke --bug unlucky-byte

# ---------------------------------------------------------------------------
# 4. no-fsync -- CrashFs crash injection (LOW confidence via this CLI).
#    Intended flow: write records under a CrashFs that drops un-fsynced data /
#    tears writes, simulate a crash, then reopen and check the prefix:
#      cargo patina run --release --seed 1 -- --bug no-fsync --iters 64
#      cargo patina run --release --seed 1 -- --verify-db <same-path> --iters 64
#    CONCERN: a std-pure binary cannot configure CrashFs (torn_write_probability,
#    crash point, cross-restart persistence) through the current native CLI, and
#    the two runs above are separate processes with separate virtual filesystems.
#    This mode most likely needs a CrashFs param surface on `native-run`/`run`,
#    or an explicit-Context harness -- which would break the no-imports rule.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 5. tight-deadline -- virtual clock + latency injection (LOW confidence via CLI).
#    Under the virtual clock the paced sleeps sum to exactly the nominal budget,
#    so with NO extra latency this stays CLEAN just like native. It only trips if
#    latency/jitter is injected onto the clock or scheduler so virtual-elapsed
#    exceeds the 2x budget.
#      cargo patina run --release --seed 1 -- --bug tight-deadline --iters 10
#    CONCERN: `native-run --net-latency-nanos` affects the NETWORK, not sleeps;
#    there is no sleep/clock-latency knob in the native CLI. Triggering this needs
#    a Latency wrapper on the clock (patina-wrapper-latency) that a std-pure
#    binary cannot request today.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 6. udp-order -- SimNet reorder/drop (LOW-MEDIUM confidence via CLI).
#    Native UDP runs over SimNet under Patina. If SimNet applies seeded reorder
#    or drop, the strictly-increasing assertion trips:
#      cargo patina explore run --release --seeds 200 -- --bug udp-order --iters 64
#    CONCERN: default SimNet delivery may be in-order/lossless; reorder and drop
#    are Fault/Latency-wrapper behaviors. `--net-latency-nanos N` adds a fixed
#    delay (may not reorder). Triggering reorder/drop likely needs a SimNet fault
#    surface on the native CLI, or an explicit-Context topology.
# ---------------------------------------------------------------------------

echo "UNTESTED SKETCH -- see per-bug CONCERN notes above before trusting any line"
