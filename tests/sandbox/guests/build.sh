#!/bin/sh
# Build the sandbox hardening guests into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?}
mkdir -p "$out"
for g in "$here"/*.c; do
    gcc -O1 -w -pthread -o "$out/$(basename "$g" .c)" "$g"
done
