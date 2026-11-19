#!/bin/sh
# Build the arm64-only guests into $1 (nothing on other machines): the stub gadget, the
# PAC-signed return address, the counter-timer reads, /dev/urandom, a BTI-marked program
# (static and dynamic) and signal handler, live SME state at a signal.
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
$cc -O1 -static -o "$out/sme-state" "$here/sme-state.c"
bti="-O1 -mbranch-protection=standard -nostartfiles -fno-stack-protector"
# shellcheck disable=SC2086
$cc $bti -static -nostdlib -o "$out/bti-static" "$here/bti.c"
# shellcheck disable=SC2086
$cc $bti -o "$out/bti-dyn" "$here/bti.c" -Wl,--no-as-needed -lc
$cc -O1 -mbranch-protection=standard -shared -fPIC -nostartfiles -Wl,-z,force-bti -o "$out/libbtisig.so" "$here/bti-sig-lib.c"
$cc -O1 -o "$out/bti-sig" "$here/bti-sig.c" -L"$out" -lbtisig -Wl,-rpath,'$ORIGIN'
