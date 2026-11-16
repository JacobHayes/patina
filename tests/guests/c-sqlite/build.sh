#!/bin/sh
# Build W3 (c-sqlite) against the system libsqlite3 (dynamic), ordinary gcc.
# Output: $1/c-sqlite/sqlite-dur ($1: the workloads root tests/guests.sh passes).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}/c-sqlite
mkdir -p "$out"
${CC:-gcc} -O1 -g -Wall -pthread -o "$out/sqlite-dur.new" "$here/sqlite_dur.c" -lsqlite3
mv "$out/sqlite-dur.new" "$out/sqlite-dur"
