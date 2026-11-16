#!/bin/sh
# Build the SDK test guests into $1: sdk-c (sdk/c/patina.h), sdk-rs (crates/patina, built with
# rustc alone), sdk-go (go/patina, stock Go, static, no cgo), and sdk-py.py with patina.py.
# Each runs the same script of operations (see guest.c); sdk-extra shows fork, execve and
# setup-complete once, in C.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O1 -Wall -Wextra -Werror -I "$root/sdk/c" -o "$out/sdk-c" "$here/guest.c"
$cc -O1 -Wall -Wextra -Werror -I "$root/sdk/c" -o "$out/sdk-extra" "$here/extra.c"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rustc -O --edition 2024 --crate-type rlib --crate-name patina_dst -o "$tmp/libpatina_dst.rlib" "$root/crates/patina/src/lib.rs"
rustc -O --edition 2024 --extern patina_dst="$tmp/libpatina_dst.rlib" -o "$out/sdk-rs" "$here/guest.rs"
(cd "$here/go" && GOCACHE=$PATINA_BUILD_DIR/gocache GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o "$out/sdk-go" .)
cp "$root/sdk/python/patina.py" "$out/patina.py"
cp "$here/guest.py" "$out/sdk-py.py"
