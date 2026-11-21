#!/usr/bin/env python3
"""What a node's peers see when its processes are killed, and what a restart finds.

    kill.py b              serve :7000 (the first process) and :7001 (a child it forks); count
                           the starts in the work tree's `starts`
    kill.py driver CYCLES  kill b and start it again CYCLES times, checking each time

On each connection b sends one line, `inc=I starts=N pid=P` (I is PATINA_INCARNATION, 0 when
it is not set), and then holds the connection open. The driver checks, for each cycle: both
connections end (end of file or a reset) once `node kill b` returns; a connect to
either port is refused while b is down; a second kill and a start while up are refused
(`EALREADY`); after `node start b` the new process reports the next incarnation and a count
that kept the last one's (the work tree stays). It prints `ok ...` lines or `FAIL: ...` and
exits 1.
"""
import errno
import os
import socket
import sys
import time

import patina


def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    held = []
    while True:
        c, _ = s.accept()
        inc = os.environ.get("PATINA_INCARNATION", "0")
        c.sendall(f"inc={inc} starts={STARTS} pid={os.getpid()}\n".encode())
        held.append(c)


def node():
    global STARTS
    try:
        with open("starts") as f:
            STARTS = int(f.read())
    except FileNotFoundError:
        STARTS = 0
    STARTS += 1
    with open("starts.tmp", "w") as f:
        f.write(str(STARTS))
    os.rename("starts.tmp", "starts")
    print(f"b: start {STARTS}, incarnation {os.environ.get('PATINA_INCARNATION', '0')}", flush=True)
    if os.fork() == 0:
        serve(7001)
    serve(7000)


def connect(port, wait=True):
    """A connection to b and its first line; with `wait`, retry while b is not listening."""
    for _ in range(400):
        c = socket.socket()
        try:
            c.connect(("b", port))
        except ConnectionRefusedError:
            c.close()
            if not wait:
                raise
            time.sleep(0.05)
            continue
        f = c.makefile("r")
        line = f.readline().strip()
        return c, f, dict(w.split("=") for w in line.split())
    raise SystemExit(f"FAIL: setup: b:{port} never listened")


def ended(c):
    c.settimeout(5)
    try:
        return c.recv(1) == b""
    except ConnectionResetError:
        return True
    except OSError:
        return False


def control_err(words):
    try:
        patina.control(words)
        return 0
    except OSError as e:
        return e.errno


def driver(cycles):
    bad = []

    def check(ok, what):
        if not ok:
            bad.append(what)
            print(f"FAIL: {what}", flush=True)

    for k in range(cycles):
        c0, f0, a = connect(7000)
        c1, f1, b1 = connect(7001)
        check(a["inc"] == str(k) and a["starts"] == str(k + 1),
              f"cycle {k}: b reports {a} (expected incarnation {k}, start {k + 1})")
        check(b1["pid"] != a["pid"], f"cycle {k}: :7001 is served by the first process")
        check(control_err("node start b") == errno.EALREADY, f"cycle {k}: a start of a running node")
        patina.control("node kill b")
        check(ended(c0) and ended(c1), f"cycle {k}: a connection to the killed node did not end")
        for p in (7000, 7001):
            try:
                connect(p, wait=False)
                check(False, f"cycle {k}: :{p} still accepts")
            except ConnectionRefusedError:
                pass
        check(control_err("node kill b") == errno.EALREADY,
              f"cycle {k}: a kill of a node that is down")
        for x in (c0, c1, f0, f1):
            x.close()
        patina.control("node start b")
    c0, _, a = connect(7000)
    check(a["inc"] == str(cycles), f"after {cycles} cycles: b reports {a}")
    if bad:
        sys.exit(1)
    print(f"ok {cycles} cycles: connections ended at each kill, connects refused while down")
    print(f"ok each restart found the work tree of the last: start {a['starts']}, incarnation {a['inc']}")


if __name__ == "__main__":
    if sys.argv[1] == "driver":
        driver(int(sys.argv[2]))
    else:
        node()
