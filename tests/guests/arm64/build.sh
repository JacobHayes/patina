#!/bin/sh
# Build the arm64-only guests into $1 (nothing on other machines): the stub gadget, the
# PAC-signed return address, the counter-timer reads, /dev/urandom.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
[ "$(uname -m)" = aarch64 ] || exit 0
cc=${CC:-gcc}
$cc -O1 -static -o "$out/stub-gadget" "$here/stub-gadget.c"
$cc -O1 -static -fno-omit-frame-pointer -mbranch-protection=standard -o "$out/pac-lr" "$here/pac-lr.c"
$cc -O1 -static -o "$out/counter" "$here/counter.c"
$cc -O1 -static -o "$out/urandom" "$here/urandom.c"
