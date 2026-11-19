#!/bin/sh
# Build the file-system guests into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
for g in fs-tour tsorder proc-policy memtest efault churn statfs sparsemap; do
    $cc -O1 -Wall -o "$out/$g" "$here/$g.c"
done
cp "$here/pyscript.py" "$out/"
