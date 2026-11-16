#!/bin/sh
# W5 (cpython): a plain script for the stock /usr/bin/python3; "building" copies it to
# $1/cpython/ ($1: the workloads root tests/guests.sh passes).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}/cpython
mkdir -p "$out"
cp "$here/w5.py" "$out/w5.py.new"
mv "$out/w5.py.new" "$out/w5.py"
