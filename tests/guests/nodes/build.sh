#!/bin/sh
# Install the node guests into $1: kv.py (a primary/backup key-value store and its driver), q3.py
# (a three-node replicated store with failover, and its driver), iso.py (what one node can see
# of another), kill.py (what a node's peers see of its kill and restart), ahead.py (runs that
# wait for a node event), disk.py (what a node's machine crash keeps of its disk, and what
# its peers see of it), wal.py (a log recovered after machine crashes) and ack2.py (a
# two-node store that acknowledges once both nodes synced a write), each with the
# Python SDK, and ctl (the C SDK's control call).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?output directory}
mkdir -p "$out"
cp "$root/sdk/python/patina.py" "$out/patina.py"
${CC:-gcc} -O1 -Wall -Wextra -Werror -I "$root/sdk/c" -o "$out/ctl" "$here/ctl.c"
for f in kv.py iso.py q3.py kill.py ahead.py disk.py wal.py ack2.py; do
    cp "$here/$f" "$out/$f"
    chmod 755 "$out/$f"
done
