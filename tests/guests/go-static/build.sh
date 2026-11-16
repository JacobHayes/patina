#!/bin/sh
# Build W4 (go-static) with the host's stock Go toolchain: plain `go build`, static (no cgo),
# no flags, no tags. Output: $1/go-static/{go-static,go-spin,go-sweep} ($1: the workloads root
# tests/guests.sh passes).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}/go-static
mkdir -p "$out"
export GOCACHE=$PATINA_BUILD_DIR/gocache GOTOOLCHAIN=local CGO_ENABLED=0
cd "$here"
go build -o "$out/go-static" ./w4
go build -o "$out/go-spin" ./spin
go build -o "$out/go-sweep" ./sweep
