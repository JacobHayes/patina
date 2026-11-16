#!/bin/sh
# W6 (shell-pipeline): a script for the system /bin/sh (dash) and /bin/bash over the system
# coreutils; "building" copies it to $1/shell-pipeline/ ($1: the workloads root tests/guests.sh
# passes).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}/shell-pipeline
mkdir -p "$out"
cp "$here/w6.sh" "$out/w6.sh.new"
chmod 755 "$out/w6.sh.new"
mv "$out/w6.sh.new" "$out/w6.sh"
