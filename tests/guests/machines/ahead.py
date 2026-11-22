#!/usr/bin/env python3
"""Runs whose threads all wait with no deadline while a machine event is ahead.

    ahead.py b [exit]   serve :7000: answer `ping` with `pong`; with `exit`, the first start
                        exits 0 once it has a connection, and a restart (PATINA_BOOT
                        >= 2) first connects to main's :7001 and says `back inc=K`
    ahead.py main kill     connect to b and wait to read, with no deadline: only the seed's
                             kill of b can end the wait
    ahead.py main restart  listen on :7001, connect to b, see the connection end when b exits,
                             and wait to accept, with no deadline: only b's restart comes
    ahead.py main heal     connect to b; at 3 s, inside the seed's partition between the
                             main and b, use control calls (`patina ctl`, `patina.control`),
                             send `ping` and wait for `pong`, with no deadline: only the heal
                             can deliver it
    ahead.py main settle   as heal, but `control("settle")` at 3 s instead: the partition
                             heals at once, and `pong` comes before the partition's own end
    ahead.py main quiet    `control("settle")`, then as kill: no kill comes

Each main prints one line and exits 0, or prints `FAIL: ...` and exits 1.
"""
import os
import socket
import subprocess
import sys
import time

import patina


def machine(args):
    inc = int(os.environ.get("PATINA_BOOT", "1")) - 1
    if args == ["exit"] and inc >= 1:
        c = socket.create_connection(("main", 7001))
        c.sendall(f"back inc={inc}\n".encode())
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.listen(8)
    while True:
        c, _ = s.accept()
        if args == ["exit"] and inc == 0:
            sys.exit(0)
        while True:
            data = c.recv(64)
            if not data:
                break
            if data == b"ping\n":
                c.sendall(b"pong\n")


def connect():
    for _ in range(400):
        c = socket.socket()
        try:
            c.connect(("b", 7000))
            return c
        except ConnectionRefusedError:
            c.close()
            time.sleep(0.05)
    raise SystemExit("FAIL: setup: b:7000 never listened")


def ended(c):
    try:
        return c.recv(1) == b""
    except ConnectionResetError:
        return True


def main(case):
    if case == "quiet":
        patina.control("settle")
        case = "kill"
    if case == "kill":
        c = connect()
        if not ended(c):
            raise SystemExit("FAIL: kill: data on the connection")
        print("kill: the connection ended")
    elif case == "restart":
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 7001))
        s.listen(1)
        c = connect()
        if not ended(c):
            raise SystemExit("FAIL: restart: data on the connection")
        a, _ = s.accept()
        print(f"restart: {a.makefile('r').readline().strip()}")
    elif case == "heal":
        c = connect()
        time.sleep(3)
        subprocess.run(["patina", "ctl", "heal", "--from", "b", "--to", "main"], check=True)
        patina.control("partition main b")
        patina.control("heal")
        c.sendall(b"ping\n")
        line = c.makefile("r").readline().strip()
        if line != "pong":
            raise SystemExit(f"FAIL: heal: {line!r}")
        print("heal: pong")
    elif case == "settle":
        c = connect()
        time.sleep(3)
        t0 = time.monotonic()
        patina.control("settle")
        c.sendall(b"ping\n")
        line = c.makefile("r").readline().strip()
        if line != "pong" or time.monotonic() - t0 > 1:
            raise SystemExit(f"FAIL: settle: {line!r} after {time.monotonic() - t0:.1f} s")
        print("settle: pong")
    else:
        raise SystemExit(f"FAIL: unknown case {case}")


if __name__ == "__main__":
    if sys.argv[1] == "main":
        main(sys.argv[2])
    else:
        machine(sys.argv[2:])
