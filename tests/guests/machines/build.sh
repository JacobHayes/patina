#!/bin/sh
# Install the machine guests into $1: kv.py (a primary/backup key-value store and its main), q3.py
# (a three-machine replicated store with failover, and its main), iso.py (what one machine can see
# of another), kill.py (what a machine's peers see of its kill and restart), ahead.py (runs that
# wait for a machine event), disk.py (what a machine crash keeps of its disk, and what
# its peers see of it), wal.py (a log recovered after machine crashes), ack2.py (a two-machine
# store that acknowledges once both machines synced a write), ka.py (TCP keepalive across machine
# failures), pause.py (what a machine and its peers see of its pauses), lease.py (a lease-based
# primary/backup service), lww.py (a last-writer-wins register on two machines) and phases.py (a
# store of puts for runs with a setup and a final check), each with
# the Python SDK; ctl (the C SDK's control call) and clockstep (a machine's timers across steps
# of its clock).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?output directory}
mkdir -p "$out"
cp "$root/sdk/python/patina.py" "$out/patina.py"
${CC:-gcc} -O1 -Wall -Wextra -Werror -I "$root/sdk/c" -o "$out/ctl" "$here/ctl.c"
${CC:-gcc} -O1 -Wall -Wextra -Werror -pthread -I "$root/sdk/c" -o "$out/clockstep" "$here/clockstep.c"
for f in kv.py iso.py q3.py kill.py ahead.py disk.py wal.py ack2.py ka.py pause.py lease.py lww.py phases.py; do
    cp "$here/$f" "$out/$f"
    chmod 755 "$out/$f"
done
