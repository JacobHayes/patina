"""sandbox.py OUT MARKER SECONDS: wait until the run writing to OUT is up and its guest stdout
(OUT/boot-1/stdout) contains MARKER, or, for MARKER "procs:N", until at least N processes of the
run are inside its PID namespace (since sandbox hardening the guest's stdout reaches OUT only at the end of
the run; every guest process holds the boundary log, so it counts as a process of the run);
then print, one per line, every namespace of the run's
processes (those most of them share) that differs from this process's own (as /proc/PID/ns/* names it), and on stderr
how many processes of the run are alive. Exit 1 if that does not happen within SECONDS of polls."""
import os
import sys
import time
from collections import Counter

out, marker, limit = os.path.realpath(sys.argv[1]) + "/", sys.argv[2].encode(), float(sys.argv[3])
procs = int(marker[6:]) if marker.startswith(b"procs:") else None
mine = {n: os.readlink(f"/proc/self/ns/{n}") for n in os.listdir("/proc/self/ns")}


def members():
    """Processes with a descriptor under OUT: (pid, its namespaces)."""
    r = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            for fd in os.listdir(f"/proc/{name}/fd"):
                if os.readlink(f"/proc/{name}/fd/{fd}").startswith(out):
                    r.append((int(name), {n: os.readlink(f"/proc/{name}/ns/{n}") for n in os.listdir(f"/proc/{name}/ns")}))
                    break
        except OSError:
            pass
    return r


# At most SECONDS of polls (more under load: the bound counts polls, not wall time).
for _ in range(int(limit / 0.05)):
    try:
        up = procs is not None or marker in open(out + "boot-1/stdout", "rb").read()
    except OSError:
        up = False
    if up:
        m = members()
        inside = [ns for _, ns in m if ns["pid"] != mine["pid"]]
        if inside and (procs is None or len(inside) >= procs):
            # The namespaces most of them share (a process caught while the sandbox is still being set
            # up can be in the new PID namespace and an older mount namespace).
            sup = dict(Counter(tuple(sorted(ns.items())) for ns in inside).most_common(1)[0][0])
            for n, v in sorted(sup.items()):
                if v != mine.get(n):
                    print(v)
            print(f"{len(m)} processes of the run alive ({len(inside)} inside its PID namespace)", file=sys.stderr)
            sys.exit(0)
    time.sleep(0.05)
sys.exit(1)
