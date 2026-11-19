#!/bin/sh
# Build the instruction-channel guests into $1.
# C with the system gcc, C++ against libstdc++, OpenSSL's libcrypto, Go static (CGO_ENABLED=0).
# The guests written in x86 assembly have arm64 twins (*-a64.c) built under the same names;
# insn-cpuid and insn-probe are x86-only.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
case $(uname -m) in
    x86_64)
        $cc -O1 -o "$out/insn" "$here/insn.c"
        $cc -O1 -o "$out/insn-cpuid" "$here/insn-cpuid.c"
        $cc -O1 -o "$out/insn-jit" "$here/insn-jit.c"
        $cc -O1 -o "$out/insn-probe" "$here/insn-probe.c"
        ;;
    *)
        $cc -O1 -o "$out/insn" "$here/insn-a64.c"
        $cc -O1 -o "$out/insn-jit" "$here/insn-jit-a64.c"
        ;;
esac
# insn-xonly: its executable segment execute-only (the read flag of every R+X PT_LOAD cleared).
$cc -O1 -static -o "$out/insn-xonly" "$here/xonly.c"
python3 -I -c '
import struct, sys
f = open(sys.argv[1], "r+b")
e = f.read(64)
phoff, phentsize, phnum = struct.unpack_from("<Q", e, 32)[0], *struct.unpack_from("<HH", e, 54)
for i in range(phnum):
    f.seek(phoff + i * phentsize)
    typ, flags = struct.unpack("<II", f.read(8))
    if typ == 1 and flags == 5:
        f.seek(phoff + i * phentsize + 4)
        f.write(struct.pack("<I", 1))
' "$out/insn-xonly"
${CXX:-g++} -O1 -o "$out/insn-rand-cpp" "$here/rand-cpp.cc"
$cc -O1 -o "$out/insn-rand-ssl" "$here/rand-ssl.c" -lcrypto
gocache=$PATINA_BUILD_DIR/gocache
(cd "$here/go-hello" && GOCACHE=$gocache GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$out/insn-go-hello" .)
