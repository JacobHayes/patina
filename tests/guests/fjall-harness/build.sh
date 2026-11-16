#!/bin/sh
# Build the fjall crash-recovery harness (W9), unmodified fjall 3.1.13 (lsm-tree 3.1.10) from
# the local crates.io cache (offline) and Patina's SDK (crates/patina, listed in deps), debug
# and release, with the ordinary toolchain; the cargo target directory is under
# PATINA_BUILD_DIR. Output: $1/fjall-harness/fjall-harness-debug and fjall-harness-release
# ($1: the workloads root tests/guests.sh passes).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}/fjall-harness
tgt=$PATINA_BUILD_DIR/fjall-harness-target
mkdir -p "$out"
cd "$here"
cargo build --quiet --offline --locked --target-dir "$tgt"
cargo build --quiet --offline --locked --release --target-dir "$tgt"
cp "$tgt/debug/fjall-harness" "$out/fjall-harness-debug"
cp "$tgt/release/fjall-harness" "$out/fjall-harness-release"
