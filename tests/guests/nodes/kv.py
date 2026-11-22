#!/usr/bin/env python3
"""A replicated key-value store on two nodes, and the driver that checks it.

    kv.py primary [bug]   serve clients on :7000; each SET is sent to the backup and answered
                          once the backup has acknowledged it (synchronous replication)
    kv.py backup [bug]    take the primary's updates on :7100, serve reads on :7001; with `bug`
                          it acknowledges an update before applying it
    kv.py driver          write, cut the link between primary and backup, observe both sides,
                          heal, check that they converge

Lines are `SET k v`, `GET k`, `DUMP`; answers `OK`, the value (`-` when absent) or the dump.
"""
import socket
import sys
import threading
import time

import patina


def lines(conn):
    buf = b""
    while True:
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode()
        d = conn.recv(4096)
        if not d:
            return
        buf += d


def listen(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    return s


def dial(host, port):
    while True:
        try:
            return socket.create_connection((host, port))
        except ConnectionRefusedError:
            time.sleep(0.05)


def serve(srv, handle):
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def primary(bug):
    data = {}
    lock = threading.Lock()
    repl = dial("backup", 7100)
    acks = lines(repl)

    def handle(c):
        for line in lines(c):
            w = line.split()
            if w[0] == "SET":
                with lock:
                    data[w[1]] = w[2]
                    repl.sendall(f"{line}\n".encode())
                    assert next(acks) == "ACK"
                c.sendall(b"OK\n")
            elif w[0] == "GET":
                c.sendall(f"{data.get(w[1], '-')}\n".encode())
            elif w[0] == "DUMP":
                c.sendall(f"{sorted(data.items())}\n".encode())

    serve(listen(7000), handle)


def backup(bug):
    data = {}
    pending = []
    cv = threading.Condition()

    def apply():
        # With the bug, updates are applied in batches, every few milliseconds.
        while True:
            time.sleep(0.005)
            with cv:
                while not pending:
                    cv.wait()
                batch = pending[:]
                del pending[:]
            data.update(batch)

    def updates(c):
        for line in lines(c):
            _, k, v = line.split()
            if bug:
                # The bug: the acknowledgement goes out before the update is applied.
                c.sendall(b"ACK\n")
                with cv:
                    pending.append((k, v))
                    cv.notify()
            else:
                data[k] = v
                c.sendall(b"ACK\n")

    def reads(c):
        for line in lines(c):
            w = line.split()
            if w[0] == "GET":
                c.sendall(f"{data.get(w[1], '-')}\n".encode())
            elif w[0] == "DUMP":
                c.sendall(f"{sorted(data.items())}\n".encode())

    threading.Thread(target=apply, daemon=True).start()
    threading.Thread(target=serve, args=(listen(7001), reads), daemon=True).start()
    serve(listen(7100), updates)


class Client:
    """A connection whose reads can time out and be taken up again."""

    def __init__(self, host, port):
        self.c = dial(host, port)
        self.buf = b""

    def ask(self, line, timeout=None):
        self.c.sendall(f"{line}\n".encode())
        return self.wait(timeout)

    def wait(self, timeout=None):
        self.c.settimeout(timeout)
        while b"\n" not in self.buf:
            d = self.c.recv(4096)
            if not d:
                fail("connection closed")
            self.buf += d
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode()


def fail(why):
    print(f"FAIL: {why}", flush=True)
    sys.exit(1)


def driver():
    p, b = Client("primary", 7000), Client("backup", 7001)
    for i in range(3):
        if p.ask(f"SET k{i} v{i}") != "OK":
            fail("SET")
        got = b.ask(f"GET k{i}")
        if got != f"v{i}":
            fail(f"stale read: the backup answered {got} for k{i} after the primary's OK")
    print("replicated: 3 keys", flush=True)

    patina.control("partition primary backup")
    try:
        p.ask("SET cut v-cut", timeout=5)
        fail("a SET completed while the backup was cut off")
    except socket.timeout:
        print("cut: the SET waits for the backup", flush=True)
    if b.ask("GET cut") != "-":
        fail("the backup applied an update across the cut")
    print("cut: the backup is behind", flush=True)
    # The pending SET holds its connection: the primary is read on another.
    if Client("primary", 7000).ask("GET cut") != "v-cut":
        fail("the primary does not hold the pending SET")

    patina.control("heal")
    if p.wait(timeout=60) != "OK":
        fail("the pending SET after the heal")
    got = b.ask("GET cut")
    if got != "v-cut":
        fail(f"stale read: the backup answered {got} after the heal and the primary's OK")
    dp, db = p.ask("DUMP"), b.ask("DUMP")
    if dp != db:
        fail(f"diverged: primary {dp}, backup {db}")
    print(f"healed: converged on {dp}", flush=True)


if __name__ == "__main__":
    role, bug = sys.argv[1], sys.argv[2:] == ["bug"]
    {"primary": primary, "backup": backup, "driver": lambda _: driver()}[role](bug)
