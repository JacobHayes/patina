#!/bin/sh
# Go compute-point guests into $1 (/guest/compute/ in the sandbox), with the stock toolchain,
# no cgo, the hook package go/patina/compute and -gcflags=all=-d=libfuzzer:
#   go-race, go-deadline  the guests (see their sources)
#   go-race-stock, go-deadline-stock  the same without the flag (they still import the package)
#   go-static             W4 (tests/guests/go-static) rebuilt with the flag and the package
#   go-noimport.err       the link error of a program built with the flag that does not import
#                         the package (fail closed); go-noimport if it linked anyway
# If the toolchain refuses to build them (a toolchain that no longer accepts the package's
# //go:linkname of the runtime's libfuzzer hooks), GO-BROKEN holds its version and error and
# this script succeeds, so other areas are not blocked; tests/compute/06-go.sh fails on it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?guest dir}
export GOCACHE=${PATINA_BUILD_DIR:?}/gocache GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=mod
flag=-gcflags=all=-d=libfuzzer
root=$(cd "$here/../../../.." && pwd)
# W4 is package main of its own module: build a copy of its sources with one more file that
# imports the package.
w4=$(mktemp -d)
trap 'rm -rf "$w4"' EXIT
cp "$root"/tests/guests/go-static/w4/*.go "$w4/"
printf 'package main\n\nimport _ "github.com/JacobHayes/patina/go/patina/compute"\n' >"$w4/compute.go"
printf 'module w4\n\ngo 1.27\n\nrequire github.com/JacobHayes/patina/go/patina v0.0.0\n\nreplace github.com/JacobHayes/patina/go/patina => %s/go/patina\n' "$root" >"$w4/go.mod"
cd "$here"
if ! log=$(go build "$flag" -o "$out/go-race" ./race 2>&1 &&
    go build "$flag" -o "$out/go-deadline" ./deadline 2>&1 &&
    go build -o "$out/go-race-stock" ./race 2>&1 &&
    go build -o "$out/go-deadline-stock" ./deadline 2>&1 &&
    (cd "$w4" && go build "$flag" -o "$out/go-static" .) 2>&1); then
    printf '%s: the Go compute guests do not build:\n%s\n' "$(go version)" "$log" | tee "$out/GO-BROKEN" >&2
fi
go build "$flag" -o "$out/go-noimport" ./noimport >"$out/go-noimport.err" 2>&1 || true
