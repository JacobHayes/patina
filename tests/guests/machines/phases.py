#!/usr/bin/env python3
"""A store of puts behind TCP, for tests that work, settle and check.

    phases.py serve [lazy]     serve :7000: `put I` appends `I` to `log` (in the disk) with
                               fsync and answers `ok`; `get` answers the puts held, space-separated;
                               a failed write or fsync answers `err`. With `lazy` it answers `ok`
                               without the fsync. On start it reads `log` back.
    phases.py work N HOST...   put 1..N on each host, 0.2 s apart; each put is sent again (on a
                               new connection after an error or a second of silence) until `ok`
    phases.py check N HOST...  the check after settle: poll each host until it answers `get` (at most 60 s
                               of virtual time), then exit 1 if a host lacks a put of 1..N

Each command prints what it did and exits 0, or prints `FAIL: ...` and exits 1.
"""
import os
import socket
import sys
import threading
import time


def serve(lazy):
    held = set()
    if os.path.exists("log"):
        held = {int(x) for x in open("log").read().split()}
    lock = threading.Lock()
    fd = os.open("log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)

    def one(c):
        for line in c.makefile("rb"):
            w = line.split()
            if w[:1] == [b"get"]:
                with lock:
                    c.sendall((" ".join(map(str, sorted(held))) + "\n").encode())
                continue
            i = int(w[1])
            with lock:
                try:
                    if i not in held:
                        b = b"%d\n" % i
                        while b:
                            b = b[os.write(fd, b):]
                        if not lazy:
                            os.fsync(fd)
                        held.add(i)
                    answer = b"ok\n"
                except OSError:
                    answer = b"err\n"
                c.sendall(answer)

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.listen(16)
    while True:
        try:
            c, _ = s.accept()
        except OSError:  # a connection reset before it was accepted
            continue
        threading.Thread(target=guard, args=(one, c), daemon=True).start()


def guard(f, c):
    try:
        f(c)
    except OSError:
        pass
    finally:
        c.close()


def ask(host, line, wait=1.0):
    """One request on a new connection: the answer, or None after an error or silence."""
    try:
        c = socket.create_connection((host, 7000), timeout=wait)
        c.settimeout(wait)
        c.sendall(line.encode())
        a = c.makefile("r").readline()
        c.close()
        return a.strip() if a.endswith("\n") else None
    except OSError:
        return None


def until(host, line, budget):
    t0 = time.monotonic()
    while time.monotonic() - t0 < budget:
        a = ask(host, line)
        if a is not None and a != "err":
            return a
        time.sleep(0.1)
    return None


def main(argv):
    cmd = argv[0]
    if cmd == "serve":
        serve(argv[1:] == ["lazy"])
    elif cmd == "work":
        n, hosts = int(argv[1]), argv[2:]
        for i in range(1, n + 1):
            for h in hosts:
                while ask(h, f"put {i}\n") != "ok":
                    time.sleep(0.05)
            time.sleep(0.2)  # the seed's timed faults come while the run waits
        print(f"work: {n} puts on {len(hosts)} hosts", flush=True)
    elif cmd == "check":
        n, hosts = int(argv[1]), argv[2:]
        for h in hosts:
            a = until(h, "get\n", 60)
            if a is None:
                raise SystemExit(f"FAIL: check: {h} never answered")
            missing = set(range(1, n + 1)) - {int(x) for x in a.split()}
            if missing:
                raise SystemExit(f"FAIL: check: {h} lost acknowledged puts {sorted(missing)}")
        print(f"check: {n} puts on each of {len(hosts)} hosts", flush=True)


main(sys.argv[1:])
