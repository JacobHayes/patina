#!/bin/sh
# Build the thread guests into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
for g in c-threads order deadlock liveness many cost spinpoints; do
    $cc -O1 -pthread -o "$out/$g" "$here/$g.c"
done
# arm64: a spin lock on exclusive pairs (no single-instruction atomics)
if [ "$(uname -m)" = aarch64 ]; then
    $cc -O1 -pthread -march=armv8-a -mno-outline-atomics -o "$out/llsc-spin" "$here/llsc-spin.c"
fi
rustc -O --edition 2021 -o "$out/rs-threads" "$here/rs-threads.rs"
