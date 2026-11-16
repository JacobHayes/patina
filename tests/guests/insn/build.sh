#!/bin/sh
# Build the instruction-channel guests into $1.
# C with the system gcc, C++ against libstdc++, OpenSSL's libcrypto, Go static (CGO_ENABLED=0).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O1 -o "$out/insn" "$here/insn.c"
$cc -O1 -o "$out/insn-cpuid" "$here/insn-cpuid.c"
$cc -O1 -o "$out/insn-jit" "$here/insn-jit.c"
$cc -O1 -o "$out/insn-probe" "$here/insn-probe.c"
${CXX:-g++} -O1 -o "$out/insn-rand-cpp" "$here/rand-cpp.cc"
$cc -O1 -o "$out/insn-rand-ssl" "$here/rand-ssl.c" -lcrypto
gocache=$PATINA_BUILD_DIR/gocache
(cd "$here/go-hello" && GOCACHE=$gocache GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$out/insn-go-hello" .)
