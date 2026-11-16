#!/bin/sh
# Build the signal guests into $1.
# C with the system gcc and glibc; go-sig with the system Go, static (CGO_ENABLED=0).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
for g in sig-basic sig-alt sig-ctx sig-fault sig-restart sig-mask sig-long sig-frame; do
    $cc -O1 -pthread -o "$out/$g" "$here/$g.c"
done
$cc -O1 -mavx2 -pthread -o "$out/sig-fp" "$here/sig-fp.c"
gocache=$PATINA_BUILD_DIR/gocache
(cd "$here/go-sig" && GOCACHE=$gocache GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$out/go-sig" .)
