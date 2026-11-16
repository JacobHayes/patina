#!/bin/sh
# Build W2 (tokio-mt) with stock cargo and tokio from the local crates.io cache (offline),
# release profile, no flags. Output: $1/tokio-mt/tokio-mt ($1: the workloads root
# tests/guests.sh passes); the cargo target directory is under PATINA_BUILD_DIR.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}/tokio-mt
mkdir -p "$out"
(cd "$here" && cargo build --release --offline --quiet --target-dir "$PATINA_BUILD_DIR/tokio-mt-target")
cp "$PATINA_BUILD_DIR/tokio-mt-target/release/tokio-mt" "$out/tokio-mt.new"
mv "$out/tokio-mt.new" "$out/tokio-mt"
