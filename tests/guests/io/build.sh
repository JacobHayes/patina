#!/bin/sh
# Build the blocking-I/O guests into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
for g in pipes atomic evloop timeouts ring iodead locks pipecost; do
    $cc -O1 -pthread -Wall -o "$out/$g" "$here/$g.c"
done
rustc -O --edition 2021 -o "$out/rs-io" "$here/rs-io.rs"
# mio from the local registry cache; the build directory is scratch, never under /src.
(cd "$here/rs-mio" && cargo build --release --offline --quiet --target-dir "$out/../rs-mio-target")
cp "$out/../rs-mio-target/release/rs-mio" "$out/rs-mio"
