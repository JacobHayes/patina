#!/usr/bin/env python3
"""What a machine crash keeps of its disk, and what its peers see of the crash.

    disk.py NAME             report the disk's `synced` and `unsynced`, write both again
                             (`synced` with fsync of the file and its directory, `unsynced`
                             without), then serve :7000
    disk.py main ROUNDS    crash machine a's machine and start it again ROUNDS times

On each connection a machine sends one line, `inc=I synced=S unsynced=U now=N` (I is
PATINA_BOOT less 1, 0 when it is not set; S and U what the files held when it started, `-`
when absent; N what `unsynced` holds now), and then holds the connection open. It writes
`s<I>` and `u<I>`.

Main checks, for each round: a reports the boot it expects, and the `synced` its
last boot wrote (fsync keeps it across a machine crash); an established connection to a
sees nothing once `crash a` returns (no end of file, no reset); a connect to a while it is
down times out (it is not refused); machine b, which never crashes, still reports what it wrote
(another machine's crash leaves its unsynced data alone). After `start a` the old connection
gets a reset at its next send (a's new machine does not know it). It counts the rounds whose
`unsynced` was not what a wrote (an unsynced write may be lost). It prints `ok ...` lines or
`FAIL: ...` and exits 1.
"""
import os
import socket
import sys
import time

import patina


def read(name):
    try:
        with open(name) as f:
            return f.read() or "-"
    except FileNotFoundError:
        return "-"


def machine():
    inc = str(int(os.environ.get("PATINA_BOOT", "1")) - 1)
    line = f"inc={inc} synced={read('synced')} unsynced={read('unsynced')}"
    print(line, flush=True)
    fd = os.open("synced", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.write(fd, f"s{inc}".encode())
    os.fsync(fd)
    os.close(fd)
    d = os.open(".", os.O_RDONLY)
    os.fsync(d)
    os.close(d)
    with open("unsynced", "w") as f:
        f.write(f"u{inc}")
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.listen(8)
    held = []
    while True:
        c, _ = s.accept()
        c.sendall(f"{line} now={read('unsynced')}\n".encode())
        held.append(c)


def connect(host):
    """A connection to `host` and its line, retrying while it is not listening."""
    for _ in range(400):
        c = socket.socket()
        c.settimeout(30)
        try:
            c.connect((host, 7000))
        except ConnectionRefusedError:
            c.close()
            time.sleep(0.05)
            continue
        line = c.makefile("r").readline().strip()
        return c, dict(w.split("=") for w in line.split())
    raise SystemExit(f"FAIL: setup: {host}:7000 never listened")


def main(rounds):
    bad = []

    def check(ok, what):
        if not ok:
            bad.append(what)
            print(f"FAIL: {what}", flush=True)

    lost = 0
    b0, _ = connect("b")
    for k in range(rounds):
        c, a = connect("a")
        check(a["inc"] == str(k), f"round {k}: a reports {a}")
        if k > 0:
            check(a["synced"] == f"s{k - 1}", f"round {k}: a lost its fsynced write: {a}")
            lost += a["unsynced"] != f"u{k - 1}"
        patina.control("crash a")
        # Silent: the connection shows nothing (until its own timeouts, which are longer).
        c.settimeout(1)
        try:
            got = c.recv(1)
            check(False, f"round {k}: the crashed machine's connection got {got!r}")
        except socket.timeout:
            pass
        except OSError as e:
            check(False, f"round {k}: the crashed machine's connection: {e}")
        # A connect to a down machine is not refused: its SYN goes unanswered.
        t = socket.socket()
        t.settimeout(2)
        try:
            t.connect(("a", 7000))
            check(False, f"round {k}: a connect to the crashed machine succeeded")
        except socket.timeout:
            pass
        except OSError as e:
            check(False, f"round {k}: a connect to the crashed machine: {e}")
        t.close()
        _, b = connect("b")
        check(b["inc"] == "0" and b["now"] == "u0", f"round {k}: b reports {b}")
        patina.control("start a")
        c2, _ = connect("a")
        c2.close()
        # The new machine answers the old connection's next segment with a reset.
        c.settimeout(30)
        try:
            c.sendall(b"x")
            got = c.recv(1)
            check(False, f"round {k}: the old connection got {got!r} after the restart")
        except ConnectionResetError:
            pass
        except OSError as e:
            check(False, f"round {k}: the old connection after the restart: {e}")
        c.close()
    c, a = connect("a")
    check(a["synced"] == f"s{rounds - 1}", f"at the end: a lost its fsynced write: {a}")
    lost += a["unsynced"] != f"u{rounds - 1}"
    b0.close()
    if bad:
        sys.exit(1)
    print(f"ok {rounds} machine crashes: fsynced writes kept, the other machine untouched, "
          f"connections silent until a reset after the restart, connects timed out")
    print(f"unsynced lost in {lost} of {rounds} crashes")


if __name__ == "__main__":
    if sys.argv[1] == "main":
        main(int(sys.argv[2]))
    else:
        machine()
