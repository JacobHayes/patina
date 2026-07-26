#!/usr/bin/env bash
###############################################################################
# UNTESTED SKETCH -- do not expect this to run yet.
#
# This is the intended shape of the LATER Patina phase, written from the
# `cargo patina` CLI (see crates/cargo-patina/src/lib.rs). It has NOT been
# executed: this change is native-only. Treat every command below as a proposal
# to validate when the Patina phase actually lands.
#
# The whole point: the SAME harness binary, with the SAME program args, becomes
# a deterministic crash-consistency fuzzer under Patina. `native-run` interposes
# std::fs so redb's file I/O flows through the crash-injecting filesystem
# (crates/patina-fs-crash), and std::thread through the deterministic scheduler
# so the concurrent snapshot readers replay identically. Compare with
# run-native.sh: only the $RUNNER definition changes; the args are identical.
###############################################################################
set -euo pipefail

# native-build links the patina-native-shim staticlib from the SURROUNDING
# Patina workspace, so it must run from the repo root, not from this testbed
# (which is its own detached workspace).
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
harness_dir="$repo_root/testbeds/redb-harness"
built_bin="$harness_dir/target/patina/redb-harness"

cd "$repo_root"

# ---------------------------------------------------------------------------
# 1. Build the harness under Patina control (cfg(patina)/cfg(dst) + shim link).
#    A package path drives the package's own `cargo build`; an explicit host
#    --target (added by native-build) keeps the flags off any build scripts.
# ---------------------------------------------------------------------------
cargo patina native-build "$harness_dir" --release --output "$built_bin"

# ---------------------------------------------------------------------------
# 2. The RUNNER indirection, mirroring run-native.sh. Under Patina the db path
#    lives in the deterministic (in-memory, crash-injecting) filesystem, so the
#    write and verify phases must observe the SAME virtual filesystem image --
#    hence `full` mode, which writes, drops the handle, and verifies in one
#    process. A crash injected between commits then surfaces as the reopen
#    (verify) seeing a prefix-consistent committed state.
# ---------------------------------------------------------------------------
RUNNER=(cargo patina native-run "$built_bin")

run() { "${RUNNER[@]}" "$@"; }

# ---------------------------------------------------------------------------
# 3. Single deterministic run at a fixed seed. Program args after `--` are the
#    harness's own flags -- byte-identical to run-native.sh.
# ---------------------------------------------------------------------------
run --seed 42 -- --seed 42 --ops 400 --db /db/redb.redb --mode full --threads 2

# ---------------------------------------------------------------------------
# 4. Seed sweep: each Patina seed is an independent deterministic world that
#    picks different crash points and different torn-write / lost-fsync
#    decisions in the crash filesystem. The harness's OWN --seed is held fixed
#    so the workload is constant and only the injected faults vary; or vary both
#    to explore the joint space.
# ---------------------------------------------------------------------------
for seed in $(seq 0 63); do
  run --seed "$seed" -- \
    --seed 42 --ops 400 --db /db/redb.redb --mode full --threads 2
done

# ---------------------------------------------------------------------------
# 5. Record a failing seed, then shrink it. `native-run --record` captures the
#    boundary trace; `minimize` delta-debugs it against an oracle that replays
#    the trace and exits non-zero while the failure reproduces (the harness
#    already exits non-zero on any integrity/torn-read/model divergence).
# ---------------------------------------------------------------------------
# run --seed 1234 --record fail.trace -- --seed 42 --ops 400 --db /db/redb.redb --mode full
# cargo patina minimize fail.trace --output fail.min.trace -- \
#   cargo patina native-run "$built_bin" --replay '$PATINA_MINIMIZE_TRACE' -- \
#     --seed 42 --ops 400 --db /db/redb.redb --mode full

# ---------------------------------------------------------------------------
# 6. Crash knobs the Patina phase must wire in (see README "Patina-phase plan"):
#    crash points injected between and inside redb commits, torn writes at the
#    fsync boundary, and directory-durability loss -- all seeded by CrashFs
#    (crates/patina-fs-crash). The invariant to enforce on reopen: the recovered
#    committed state is a PREFIX of the writer's commit history (redb never
#    exposes a partial or reordered commit), which the harness checks by
#    matching the verify hash against a published set of per-commit hashes.
# ---------------------------------------------------------------------------
echo "UNTESTED SKETCH complete -- validate each step when the Patina phase lands."
