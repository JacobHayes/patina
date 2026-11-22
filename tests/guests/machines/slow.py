#!/usr/bin/env python3
"""A server slow to start, for runs with `ready` probes.

    slow.py [ARGS]   write 20 lines to `warm` (in the disk), each synced, 0.1 s apart, then
                     become `phases.py serve ARGS`; a failed write or sync (a fault during its
                     start) prints `FAIL: serve: start: ...` and exits 1
"""
import os
import sys
import time

fd = os.open("warm", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
for i in range(20):
    try:
        os.write(fd, b"%d\n" % i)
        os.fsync(fd)
    except OSError as e:
        raise SystemExit(f"FAIL: serve: start: {e}")
    time.sleep(0.1)
os.close(fd)
phases = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phases.py")
os.execv(sys.executable, [sys.executable, phases, "serve", *sys.argv[1:]])
