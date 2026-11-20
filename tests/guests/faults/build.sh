#!/bin/sh
# Build the fault and durability guests into $1. memfault is static (memory requests at the syscall level, no loader);
# window, mapends and mapshare use the C SDK (sdk/c, listed in deps).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
for g in io-errors short delay randops closedir; do
    $cc -O1 -Wall -o "$out/$g" "$here/$g.c"
done
$cc -O1 -Wall -o "$out/ack-log" "$here/acklog.c"
$cc -O1 -Wall -o "$out/errseq" "$here/errseq.c"
$cc -O1 -Wall -I "$here/../../../sdk/c" -o "$out/window" "$here/window.c"
$cc -O1 -Wall -I "$here/../../../sdk/c" -o "$out/mapends" "$here/mapends.c"
$cc -O1 -Wall -I "$here/../../../sdk/c" -o "$out/mapshare" "$here/mapshare.c"
$cc -O1 -Wall -static -pthread -o "$out/memfault" "$here/memfault.c"
cp "$here/sqlite_rows.py" "$out/"
