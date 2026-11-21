#!/usr/bin/env python3
"""A two-node store that acknowledges a write once both nodes hold it on disk.

    ack2.py a                primary: append each `put I` to `log` with fsync, forward it to b,
                             answer `ok I` once b has answered; serve :7000
    ack2.py b [MODE] [init]  backup: append each `put I` to `log` with fsync, then answer
                             `ok I`; MODE `early` answers before the append and its fsync,
                             `lazy` answers at once and appends the put when its next request
                             comes; `init` syncs b's directory when it first serves a request, on
                             its first start only (no PATINA_INCARNATION): a crash point before
                             any put
    ack2.py driver N [wait]  put 1..N through a, then read both logs back; with `wait`, first
                             wait for b to answer a `get`

A node recovers its log on every boot and ignores a `put` it already holds, so a put sent
again after a crash is applied once. A node serves each connection in a thread of its own, one
put at a time. Node a sends each put to b on one connection and, when b
does not answer within a second (b's machine crashed: silence) or the connection fails, connects
again and sends it again. The driver does the same with a. Each node answers `get` with its
records, space-separated.

The driver prints `ack I` for each acknowledged put, then reads both logs (waiting for a node
that is down) and prints `ok N acknowledged, a holds A, b holds B`, or `FAIL: acknowledged I
lost on NODE` (and on standard error which node lost one) and exits 1. With `early`, a crash of b's machine between its answer and its
fsync loses an acknowledged put when the answer reached a before the crash. With `lazy` it always
does: a sends the next request only after the answer, so a crash at a point of that append
(b's first such point is the `create` of `log`) follows the acknowledgement.
"""
import os
import socket
import sys
import threading
import time

import patina


def recover():
    try:
        with open("log") as f:
            return {int(x) for x in f.read().split()}
    except FileNotFoundError:
        return set()


def append(held, i):
    fd = os.open("log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.write(fd, f"{i}\n".encode())
    os.fsync(fd)
    os.close(fd)
    if len(held) == 0:
        d = os.open(".", os.O_RDONLY)
        os.fsync(d)
        os.close(d)
    held.add(i)


def connect(host, port, attempts=600):
    """A connection to `host`, retrying while it is down or not listening yet."""
    for _ in range(attempts):
        c = socket.socket()
        c.settimeout(1)
        try:
            c.connect((host, port))
            return c, c.makefile("r")
        except OSError:
            c.close()
            time.sleep(0.05)
    raise SystemExit(f"FAIL: {host}:{port} never answered")


def call(peer, host, port, line):
    """Send `line` and read the answer, connecting again and resending until one comes."""
    while True:
        if peer[0] is None:
            peer[0], peer[1] = connect(host, port)
        try:
            peer[0].sendall(line.encode())
            got = peer[1].readline()
            if got:
                return got.strip()
        except OSError:
            pass
        peer[0].close()
        peer[0] = None


def serve(name, mode, init):
    held = recover()
    initial = [bool(init) and "PATINA_INCARNATION" not in os.environ]
    pending = []
    lock = threading.Lock()
    b = [None, None]

    def conn(c):
        f = c.makefile("r")
        try:
            for line in f:
                w = line.split()
                with lock:
                    if initial[0]:
                        initial[0] = False
                        d = os.open(".", os.O_RDONLY)
                        os.fsync(d)
                        os.close(d)
                    for i in pending:
                        if i not in held:
                            append(held, i)
                    pending.clear()
                    if w[0] == "get":
                        c.sendall((" ".join(map(str, sorted(held))) + "\n").encode())
                        continue
                    i = int(w[1])
                    if name == "a":
                        if i not in held:
                            append(held, i)
                        call(b, "b", 7000, f"put {i}\n")
                    elif mode == "early":
                        c.sendall(f"ok {i}\n".encode())
                        if i not in held:
                            append(held, i)
                        continue
                    elif mode == "lazy":
                        c.sendall(f"ok {i}\n".encode())
                        pending.append(i)
                        continue
                    elif i not in held:
                        append(held, i)
                    c.sendall(f"ok {i}\n".encode())
        except OSError:
            pass
        c.close()

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.listen(8)
    while True:
        c, _ = s.accept()
        threading.Thread(target=conn, args=(c,), daemon=True).start()


def driver(n, wait):
    a = [None, None]
    call(a, "a", 7000, "get\n")
    patina.setup_complete()
    if wait:
        p = [None, None]
        call(p, "b", 7000, "get\n")
        p[0].close()
    for i in range(1, n + 1):
        call(a, "a", 7000, f"put {i}\n")
        print(f"ack {i}", flush=True)
    a[0].close()
    held = {}
    for node in "ab":
        p = [None, None]
        held[node] = {int(x) for x in call(p, node, 7000, "get\n").split()}
        p[0].close()
    for i in range(1, n + 1):
        for node in "ab":
            if i not in held[node]:
                print(f"FAIL: acknowledged {i} lost on {node}", flush=True)
                sys.exit(f"FAIL: acknowledged put lost on {node}")
    print(f"ok {n} acknowledged, a holds {len(held['a'])}, b holds {len(held['b'])}", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "driver":
        driver(int(sys.argv[2]), sys.argv[3:] == ["wait"])
    else:
        serve(sys.argv[1], next((m for m in sys.argv[2:] if m != "init"), None), "init" in sys.argv[2:])
