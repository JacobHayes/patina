#!/bin/sh
# Build the sweep guest (bugs.c, with the C SDK) into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?output directory}
mkdir -p "$out"
${CC:-gcc} -O1 -Wall -Wextra -Werror -pthread -I "$root/sdk/c" -o "$out/sweep-bugs" "$here/bugs.c"
