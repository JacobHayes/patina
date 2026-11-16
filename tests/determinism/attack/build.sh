#!/bin/sh
# Build the determinism attack guests into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
for g in dents pipebuf epollorder churn addr sigstorm uninit scmrights timeprobe initstack; do
    $cc -O1 -w -pthread -o "$out/$g" "$here/$g/$g.c"
done
for g in envprobe sockprobe pipeprobe procread memprobe coreprobe fdexhaust fillfs stdoutprobe stdoutlong; do
    $cc -O1 -w -pthread -o "$out/$g" "$here/probe/$g.c"
done
for g in "$here"/contain/*.c; do
    [ -e "$g" ] || continue
    n=$(basename "$g" .c)
    $cc -O1 -w -pthread -o "$out/$n" "$g"
done
for g in "$here"/insn/*.c; do
    [ -e "$g" ] || continue
    $cc -O1 -w -o "$out/$(basename "$g" .c)" "$g"
done
$cc -O1 -w -shared -fPIC -o "$out/skew.so" "$here/probe/skew.c" -ldl
