#!/bin/sh
# Build the UDP guests into $1: C (udp), Go (go-udp, CGO_ENABLED=0), tokio (tokio-udp), Python.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O1 -Wall -Wno-unused-result -o "$out/udp" "$here/udp.c"
(cd "$here/tokio-udp" && cargo build --release --offline --quiet --target-dir "$out/../tokio-udp-target")
cp "$out/../tokio-udp-target/release/tokio-udp" "$out/tokio-udp"
gocache=$PATINA_BUILD_DIR/gocache
(cd "$here/go-udp" && GOCACHE=$gocache GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$out/go-udp" .)
cp "$here/udp.py" "$out/udp.py"
chmod 755 "$out/udp.py"
