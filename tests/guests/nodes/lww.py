#!/usr/bin/env python3
"""A last-writer-wins register on two nodes, and its client.

    lww.py a|b [BUG]   serve :7002: `PUT V CTX` stamps V, keeps it if its stamp is the larger,
                       sends it to the other node, and answers `OK STAMP` once the other node
                       has it; `GET` answers `V STAMP`
    lww.py driver N    put 1..N, each after the last was acknowledged, alternately through a
                       and b, 100 ms apart; after each, check that both nodes keep it

A stamp is a node's realtime clock (time.time()). Each put carries the stamp of the last
acknowledgement the client saw (CTX), and the node stamps the put with the larger of its
clock and CTX plus a microsecond, so a put is stamped after every put it follows (a hybrid
logical clock). Planted bug (BUG, given to both nodes):
    wallclock   the node stamps a put with its own clock only: under clock-skew-ms, a node
                whose clock is behind the other's by more than the time between two puts
                stamps the later put lower, and both nodes keep the earlier value
The driver prints `ok ...` or `FAIL: lost update: ...` and exits 1.
"""
import socket
import sys
import threading
import time

BUG = ""


def serve_node(me):
    other = "b" if me == "a" else "a"
    st = {"v": 0, "ts": 0.0}
    mu = threading.Lock()
    peer = {}

    def keep(v, ts):
        with mu:
            if (ts, v) > (st["ts"], st["v"]):
                st["v"], st["ts"] = v, ts

    def to_peer(words):
        while True:
            try:
                if "c" not in peer:
                    c = socket.create_connection((other, 7002))
                    peer["c"], peer["f"] = c, c.makefile("r")
                peer["c"].sendall((words + "\n").encode())
                return peer["f"].readline()
            except OSError:
                peer.clear()
                time.sleep(0.1)

    def serve(c):
        for w in c.makefile("r"):
            w = w.split()
            if w[0] == "PUT":
                v, ctx = int(w[1]), float(w[2])
                ts = time.time()
                if BUG != "wallclock":
                    ts = max(ts, ctx + 1e-6)
                keep(v, ts)
                to_peer(f"SET {v} {ts!r}")
                c.sendall(f"OK {ts!r}\n".encode())
            elif w[0] == "SET":
                keep(int(w[1]), float(w[2]))
                c.sendall(b"OK\n")
            else:
                with mu:
                    c.sendall(f"V {st['v']} {st['ts']!r}\n".encode())

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7002))
    s.listen(8)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def driver(n):
    conns = {}
    for p in ("a", "b"):
        while p not in conns:
            try:
                c = socket.create_connection((p, 7002))
                conns[p] = (c, c.makefile("r"))
            except OSError:
                time.sleep(0.1)

    def ask(p, words):
        c, f = conns[p]
        c.sendall((words + "\n").encode())
        return f.readline().split()

    ctx = 0.0
    for v in range(1, n + 1):
        r = ask("ab"[v % 2], f"PUT {v} {ctx!r}")
        ctx = float(r[1])
        for p in ("a", "b"):
            g = ask(p, "GET")
            if int(g[1]) != v:
                print(f"FAIL: lost update: {p} keeps {g[1]} after {v} was acknowledged",
                      flush=True)
                sys.exit(1)
        time.sleep(0.1)
    print(f"ok both nodes kept each of {n} puts", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "driver":
        driver(int(sys.argv[2]))
    else:
        BUG = sys.argv[2] if len(sys.argv) > 2 else ""
        serve_node(sys.argv[1])
