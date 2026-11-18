#!/bin/sh
# Counter-preemption guests into $1/counters/ (/guest/counters/ in the sandbox), stock compilers
# (counter preemption works on unrebuilt binaries): compute (gcc), and the syscall-free races
# races and pool (clang when present, as measured; else gcc); on arm64 excl, exclusive accesses
# (static, no outlined atomics: its own exclusive instructions are what it tests), and
# excl-many, the same with more exclusive instructions than one process's patch table holds.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?guest dir}/counters
mkdir -p "$out"
gcc -O2 -pthread -o "$out/compute" "$here/compute.c" -lm
cc=$(command -v clang || echo gcc)
for p in races pool; do
    "$cc" -O1 -g -pthread -o "$out/$p" "$here/$p.c"
done
if [ "$(uname -m)" = aarch64 ]; then
    gcc -O1 -static -march=armv8-a -mno-outline-atomics -o "$out/excl" "$here/excl.c"
    gcc -O1 -static -march=armv8-a -mno-outline-atomics -DMANY -o "$out/excl-many" "$here/excl.c"
fi
