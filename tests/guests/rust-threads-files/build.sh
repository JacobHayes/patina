#!/bin/sh
# Build W1 (rust-threads-files) with the ordinary rustc, std only.
# Output: $1/rust-threads-files/ ($1: the workloads root tests/guests.sh passes).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}/rust-threads-files
mkdir -p "$out"
rustc --edition 2021 -O -o "$out/rust-threads-files.new" "$here/main.rs"
mv "$out/rust-threads-files.new" "$out/rust-threads-files"
