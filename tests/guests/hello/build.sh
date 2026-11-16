#!/bin/sh
# Build the basic guests (hello in four image kinds, spin, getppid) into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O1 -static -o "$out/hello-static" "$here/hello.c"
$cc -O1 -static-pie -fPIE -o "$out/hello-spie" "$here/hello.c"
$cc -O1 -o "$out/hello-dyn" "$here/hello.c"
rustc -O --edition 2021 -o "$out/hello-rs" "$here/hello.rs"
$cc -O1 -static -o "$out/unlisted" "$here/unlisted.c"
$cc -O1 -static -o "$out/spin" "$here/spin.c"
$cc -O1 -static -o "$out/getppid" "$here/getppid.c"
