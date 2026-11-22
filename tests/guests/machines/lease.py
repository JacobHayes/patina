#!/usr/bin/env python3
"""A lease-based primary/backup service, and its client.

    lease.py s [BUG]                 the store and lease authority: serve :7000
    lease.py p1|p2 [BUG]             a replica: hold the lease when it can, serve :7001
    lease.py main SECONDS [steps]  write and read for SECONDS of virtual time, then check;
                                     with `steps`, also step a replica's clock back now and then

The store grants one lease at a time, for LEASE ms of its own monotonic clock, with a token
that grows with each new holder. A replica asks for the lease (or renews it) every 300 ms
and counts it valid until the time it sent the request plus LEASE minus a safety margin, on
its own monotonic clock; on a new token it first reads the current value from the store. A
replica that holds the lease serves a write (it checks the lease, works 50 ms on its own log,
sends the write to the store with its token, and acknowledges once the store accepted) and a
read (it checks the lease and answers its value). The store fences: a write whose token is
not the current lease's is refused.

Main writes 1, 2, 3, ... and reads in turn, each through whichever replica answers, and
checks: no read answers a value older than a write acknowledged before the read was sent
(`stale read`); at the end, every acknowledged write is in the store's log (`lost write`) and
no write was accepted with a token other than the current lease's (`stale write`). It prints
`ok ...` or `FAIL: ...` and exits 1. With `steps`, every 2 to 5 s it steps the clock of p1 or
p2 back by 2 to 6 s (`clock NAME`), which a monotonic lease does not notice.

Planted bugs (BUG, given to s and to both replicas):
    nofence    the store does not fence: a replica paused after its check and resumed after
               its lease ran out (and another took it) writes as primary
    realtime   a replica measures its lease on CLOCK_REALTIME (time.time()): cut off from the
               store, a replica whose clock was stepped back keeps answering reads after the
               store gave the lease to the other, with a value older than the other's writes
"""
import random
import socket
import sys
import threading
import time

LEASE = 2.0
MARGIN = 0.2
BUG = ""


def lines(c):
    f = c.makefile("r")
    for line in f:
        yield line.split()


def listen(port, serve):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def dial(host, port):
    while True:
        try:
            return socket.create_connection((host, port))
        except OSError:
            time.sleep(0.1)


def store():
    state = {"token": 0, "holder": None, "exp": 0.0, "log": [], "value": 0}
    mu = threading.Lock()

    def serve(c):
        for w in lines(c):
            with mu:
                now = time.monotonic()
                if w[0] == "ACQ":
                    if state["holder"] == w[1] and now < state["exp"]:
                        state["exp"] = now + LEASE
                        r = f"OK {state['token']}"
                    elif state["holder"] is None or now >= state["exp"]:
                        state["token"] += 1
                        state["holder"], state["exp"] = w[1], now + LEASE
                        r = f"OK {state['token']}"
                    else:
                        r = "NO"
                elif w[0] == "W":
                    tok = int(w[2])
                    if BUG != "nofence" and tok != state["token"]:
                        r = "FENCED"
                    else:
                        state["log"].append((int(w[3]), w[1], tok, state["token"]))
                        state["value"] = max(state["value"], int(w[3]))
                        r = "OK"
                elif w[0] == "G":
                    r = f"V {state['value']}"
                else:
                    r = " ".join(f"{v}:{n}:{t}:{cur}" for v, n, t, cur in state["log"])
            c.sendall((r + "\n").encode())

    listen(7000, serve)


def clock():
    return time.time() if BUG == "realtime" else time.monotonic()


def replica(name):
    lease = {"token": 0, "until": 0.0, "value": 0}
    mu = threading.Lock()
    s = dial("s", 7000)
    sf = s.makefile("r")

    def call(words):
        with mu:
            s.sendall((words + "\n").encode())
            return sf.readline().split()

    def renew():
        while True:
            t = clock()
            r = call(f"ACQ {name}")
            if r[0] == "OK":
                tok = int(r[1])
                if tok != lease["token"]:
                    lease["until"] = 0.0
                    lease["value"] = int(call("G")[1])
                    lease["token"] = tok
                lease["until"] = t + LEASE - MARGIN
            time.sleep(0.3)

    def serve(c):
        for w in lines(c):
            if clock() >= lease["until"]:
                c.sendall(b"NOT\n")
                continue
            if w[0] == "R":
                c.sendall(f"V {lease['value']}\n".encode())
                continue
            tok = lease["token"]
            time.sleep(0.05)  # its own log
            r = call(f"W {name} {tok} {w[1]}")
            if r[0] == "OK":
                lease["value"] = max(lease["value"], int(w[1]))
            c.sendall(b"ACK\n" if r[0] == "OK" else b"NOT\n")

    threading.Thread(target=renew, daemon=True).start()
    listen(7001, serve)


def main(seconds, steps):
    import patina

    conns = {}

    def ask(p, words):
        try:
            if p not in conns:
                c = socket.create_connection((p, 7001), timeout=1)
                conns[p] = (c, c.makefile("r"))
            c, f = conns[p]
            c.sendall((words + "\n").encode())
            return f.readline().split() or None
        except OSError:
            # No answer in a second (a paused replica, a cut link): a new connection next time.
            conns.pop(p, None)
            return None

    def stepper():
        while True:
            time.sleep(random.uniform(2, 5))
            p = random.choice(["p1", "p2"])
            patina.control(f"clock {p} -{random.randint(2, 6)}s")

    if steps:
        threading.Thread(target=stepper, daemon=True).start()
    acked, v, reads = [], 0, 0
    top = 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        v += 1
        for p in ("p1", "p2"):
            if ask(p, f"W {v}") == ["ACK"]:
                acked.append(v)
                top = v
                break
        else:
            time.sleep(0.1)
        floor = top
        for p in ("p1", "p2"):
            r = ask(p, "R")
            if r and r[0] == "V":
                reads += 1
                if int(r[1]) < floor:
                    print(f"FAIL: stale read: {p} answered {r[1]} after {floor} was acknowledged",
                          flush=True)
                    sys.exit(1)
                break
    s = dial("s", 7000)
    s.sendall(b"LOG\n")
    log = [e.split(":") for e in s.makefile("r").readline().split()]
    have = {int(e[0]) for e in log}
    lost = [x for x in acked if x not in have]
    stale = [e for e in log if e[2] != e[3]]
    if stale:
        e = stale[0]
        print(f"FAIL: stale write: {e[0]} from {e[1]} with token {e[2]}, the lease's {e[3]} "
              f"({len(stale)} in all)", flush=True)
        sys.exit(1)
    if lost:
        print(f"FAIL: lost write: {lost[0]} acknowledged, not in the store ({len(lost)} in all)",
              flush=True)
        sys.exit(1)
    tokens = len({e[2] for e in log})
    print(f"ok {len(acked)} writes acknowledged of {v}, {reads} reads, {len(log)} in the store, "
          f"{tokens} lease holders", flush=True)


if __name__ == "__main__":
    who = sys.argv[1]
    if who == "main":
        main(float(sys.argv[2]), len(sys.argv) > 3 and sys.argv[3] == "steps")
    else:
        BUG = sys.argv[2] if len(sys.argv) > 2 else ""
        store() if who == "s" else replica(who)
