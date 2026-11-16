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
rustc -O --edition 2021 -o "$out/rs-threads" "$here/rs-threads.rs"
