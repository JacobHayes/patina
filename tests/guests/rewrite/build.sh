#!/bin/sh
# Stock programs for the rewriter's differential (tests/rewrite) into $1, each statically linked so
# that the rewritten file holds its runtime and C library too. Their output depends only on their
# input: threads and goroutines meet at joins, and results are printed in a fixed order.
#   rw-c, rw-c-spie   diff.c, static and static-PIE: qsort, snprintf, recursion, threads with
#                     a mutex and atomics
#   rw-cxx            diff.cc, static: threads, std::atomic, exceptions, virtual calls, maps
#   rw-rs             diff.rs, static-PIE (crt-static): threads, channels, Mutex, RwLock, atomics
#   rw-go             go/, static (no cgo): goroutines, channels, maps, sort, sync/atomic
#   rw-fid            fidelity.c, dynamic (PIE): what a program sees of its patched code
#                     (tests/rewrite/03-fidelity; x86_64 assembly, built on x86_64 only)
#   rw-interior       interior.S, static and static-PIE (rw-interior-pie), no C library: jumps
#                     the rewriter cannot see into its group patches (tests/rewrite/04-interior;
#                     x86_64 only)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O2 -static -pthread -o "$out/rw-c" "$here/diff.c"
$cc -O2 -static-pie -fPIE -pthread -o "$out/rw-c-spie" "$here/diff.c"
${CXX:-g++} -O2 -static -pthread -o "$out/rw-cxx" "$here/diff.cc"
rustc -O --edition 2021 -C target-feature=+crt-static -o "$out/rw-rs" "$here/diff.rs"
machine=$(uname -m)
if [ "$machine" = x86_64 ]; then
    $cc -O1 -rdynamic -o "$out/rw-fid" "$here/fidelity.c"
    $cc -nostdlib -static -no-pie -o "$out/rw-interior" "$here/interior.S"
    $cc -nostdlib -static-pie -o "$out/rw-interior-pie" "$here/interior.S"
fi
(cd "$here/go" && GOCACHE=${PATINA_BUILD_DIR:?}/gocache GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$out/rw-go" .)
