#!/bin/sh
# Build the guests of the outside checks (tests/oracles) into $1: oracles-files (paths a checker
# reads from `patina log events`), oracles-marklog (an SDK mark after each record).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O1 -Wall -Wextra -Werror -o "$out/oracles-files" "$here/files.c"
$cc -O1 -Wall -Wextra -Werror -I "$root/sdk/c" -o "$out/oracles-marklog" "$here/marklog.c"
