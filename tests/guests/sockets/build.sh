#!/bin/sh
# Build the network guests into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O1 -Wall -Wno-unused-result -o "$out/sockets" "$here/sockets.c"
rustc -O --edition 2021 -o "$out/rs-net" "$here/rs-net.rs"
(cd "$here/tokio-echo" && cargo build --release --offline --quiet --target-dir "$out/../tokio-echo-target")
cp "$out/../tokio-echo-target/release/tokio-echo" "$out/tokio-echo"
gocache=$PATINA_BUILD_DIR/gocache
(cd "$here/go-net" && GOCACHE=$gocache GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$out/go-net" .)
cp "$here/py-net.py" "$out/py-net.py"
chmod 755 "$out/py-net.py"
