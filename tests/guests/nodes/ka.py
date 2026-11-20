#!/usr/bin/env python3
"""TCP keepalive across node failures.

    ka.py b             serve :7000: echo each line back, with keepalive on every connection
                        (idle 2 s, interval 1 s, 3 probes: a 5 s budget); print how each ends
    ka.py driver MODE   connect to b with the same keepalive, have one line echoed, then wait
                        for the connection's next event:
      crash    b's machine crashes and stays down: ETIMEDOUT at the budget after the echo
      ut       the same with TCP_USER_TIMEOUT 3500 ms and 9 probes: ETIMEDOUT at the first
               probe 3.5 s after the echo (4 s), not at idle + 9 intervals
      restart  b's machine crashes and is started again 2.5 s later: the next probe reaches a
               machine without the connection, whose RST gives ECONNRESET before the budget
      short    the link is cut both ways for 3 s: nothing happens, and a second line echoes
      long     the link is cut both ways for 10 s: ETIMEDOUT at the budget, on b's side too
      pause-short, pause-long
               b is paused (`node pause b`) for 3 s or 10 s: a probe to a paused machine goes
               unanswered as across a cut, so the same

Times are virtual. It prints `ok MODE: ...` or `FAIL: ...` and exits 1.
"""
import errno
import socket
import sys
import threading
import time

import patina

IDLE, INTVL, CNT = 2, 1, 3
BUDGET = IDLE + CNT * INTVL


def keepalive(c, cnt=CNT):
    c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, IDLE)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, INTVL)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, cnt)


def ending(c):
    """How the connection ends: (errno name or "eof", seconds after the call)."""
    t = time.monotonic()
    try:
        d = c.recv(100)
        what = "eof" if d == b"" else f"data {d!r}"
    except OSError as e:
        what = errno.errorcode.get(e.errno, str(e.errno))
    return what, time.monotonic() - t


def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.listen(8)
    keepalive(s)  # accepted connections inherit it
    while True:
        c, _ = s.accept()
        threading.Thread(target=echo, args=(c,), daemon=True).start()


def echo(c):
    while True:
        t = time.monotonic()
        try:
            d = c.recv(100)
        except OSError as e:
            print(f"b: {errno.errorcode[e.errno]} after {time.monotonic() - t:.3f} s", flush=True)
            return
        if not d:
            print("b: end of file", flush=True)
            return
        c.sendall(d)


def fail(msg):
    print(f"FAIL: {msg}", flush=True)
    sys.exit(1)


def later(seconds, *words):
    def run():
        time.sleep(seconds)
        for w in words:
            patina.control(w)
    th = threading.Thread(target=run)
    th.start()
    return th


def driver(mode):
    for _ in range(400):
        try:
            c = socket.create_connection(("b", 7000))
            break
        except ConnectionRefusedError:
            time.sleep(0.05)
    else:
        fail("b never listened")
    keepalive(c, 9 if mode == "ut" else CNT)
    if mode == "ut":
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 3500)
    c.sendall(b"one\n")
    if c.recv(100) != b"one\n":
        fail("no echo")
    th = None
    if mode in ("crash", "ut"):
        patina.control("node kill b")
    elif mode == "restart":
        patina.control("node kill b")
        th = later(2.5, "node start b")
    elif mode in ("short", "long"):
        patina.control("net cut driver b")
        th = later(3 if mode == "short" else 10, "net heal")
    elif mode in ("pause-short", "pause-long"):
        patina.control("node pause b")
        th = later(3 if mode == "pause-short" else 10, "node resume b")
    else:
        fail(f"mode {mode}")
    if mode in ("short", "pause-short"):
        th.join()
        time.sleep(BUDGET)
        c.sendall(b"two\n")
        what, dt = ending(c)
        if what != "data b'two\\n'":
            fail(f"{mode}: after the end: {what}")
        print(f"ok {mode}: the connection survived 3 s; a line echoed after it")
        return
    what, dt = ending(c)
    want = {"crash": "ETIMEDOUT", "ut": "ETIMEDOUT", "long": "ETIMEDOUT", "pause-long": "ETIMEDOUT",
            "restart": "ECONNRESET"}[mode]
    at = {"crash": BUDGET, "ut": 4, "long": BUDGET, "pause-long": BUDGET}.get(mode)
    print(f"{mode}: {what} {dt:.3f} s after the echo", flush=True)
    if what != want:
        fail(f"{mode}: {what}, Linux gives {want}")
    if at is not None and not at - 0.01 <= dt < at + 0.05:
        fail(f"{mode}: {what} after {dt:.3f} s, Linux after {at} s")
    if mode == "restart" and dt >= BUDGET:
        fail(f"restart: the reset came after the budget ({dt:.3f} s)")
    if th:
        th.join()
    print(f"ok {mode}")


if __name__ == "__main__":
    if sys.argv[1] == "b":
        serve()
    else:
        driver(sys.argv[2])
