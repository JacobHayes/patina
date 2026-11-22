#!/usr/bin/env python3
"""What a machine's peers see of its pauses, and what the paused machine sees.

    pause.py b               serve :7000; each line read is answered with `t=MS gap=MS`, b's
                             monotonic clock and the longest gap its ticker (a thread that
                             sleeps 100 ms in a loop) has seen
    pause.py main script   pause and resume b with `pause b` / `resume b`, checking
                             what main and b see
    pause.py main seed S   ask b every 500 ms for S seconds of virtual time (the seed's
                             pauses act); print the longest wait for an answer
    pause.py main stuck    pause b and wait for b to send: nothing else can happen (b's
                             interval timer firing while it is paused changes nothing)

`script` checks: a connection to b survives a pause; b answers nothing while paused (a read
with a 2 s timeout times out) and answers at once after the resume, its clock showing the time
paused (its timers did not fire while paused, and fired once it ran again); a sender's
TCP_USER_TIMEOUT fires while b is paused and the connection then reports ETIMEDOUT; a pause of
a paused machine and a resume of a running one are EALREADY; a paused machine can be killed, and a
pause of a machine that is down is EAGAIN. It prints `ok ...` lines or `FAIL: ...` and exits 1.
"""
import errno
import signal
import socket
import sys
import threading
import time

import patina

GAP = 0.0


def ticker():
    global GAP
    last = time.monotonic()
    while True:
        time.sleep(0.1)
        now = time.monotonic()
        GAP = max(GAP, now - last)
        last = now


def machine():
    threading.Thread(target=ticker, daemon=True).start()
    # A periodic timer as well: while b is paused it keeps firing, and keeps nothing alive.
    signal.signal(signal.SIGALRM, lambda *_: None)
    signal.setitimer(signal.ITIMER_REAL, 0.1, 0.1)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.listen(8)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def serve(c):
    f = c.makefile("r")
    for _ in f:
        try:
            c.sendall(f"t={int(time.monotonic() * 1000)} gap={int(GAP * 1000)}\n".encode())
        except OSError:
            return


def fail(why):
    print(f"FAIL: {why}", flush=True)
    sys.exit(1)


def connect():
    for _ in range(200):
        c = socket.socket()
        try:
            c.connect(("b", 7000))
            return c, c.makefile("r")
        except ConnectionRefusedError:
            c.close()
            time.sleep(0.05)
    fail("b never listened")


def ask(c, f):
    c.sendall(b"?\n")
    line = f.readline()
    if not line:
        fail("b closed the connection")
    return dict((k, int(v)) for k, v in (w.split("=") for w in line.split()))


def ctl(words, want=0):
    try:
        patina.control(words)
        got = 0
    except OSError as e:
        got = e.errno
    if got != want:
        fail(f"{words}: errno {got}, expected {want}")


def script():
    c, f = connect()
    a = ask(c, f)
    ctl("pause b")
    ctl("pause b", errno.EALREADY)
    t0 = time.monotonic()
    c.sendall(b"?\n")
    c.settimeout(2)
    try:
        line = f.readline()
        fail(f"b answered while paused: {line!r}")
    except (TimeoutError, socket.timeout):
        pass
    waited = time.monotonic() - t0
    ctl("resume b")
    ctl("resume b", errno.EALREADY)
    c.settimeout(None)
    # The makefile reader may be left unusable by the timeout: read from a fresh one.
    f = c.makefile("r")
    b = dict((k, int(v)) for k, v in (w.split("=") for w in f.readline().split()))
    # (Both in whole ms: a ms of rounding.)
    if b["t"] - a["t"] + 1 < waited * 1000:
        fail(f"b's clock moved {b['t'] - a['t']} ms over a {int(waited * 1000)} ms pause")
    if b["gap"] + 1 < waited * 1000:
        fail(f"b's ticker saw a longest gap of {b['gap']} ms over a {int(waited * 1000)} ms pause")
    print(f"ok pause: no answer for {int(waited * 1000)} ms, then at once; b's clock moved "
          f"{b['t'] - a['t']} ms, its ticker's longest gap {b['gap']} ms; the connection kept",
          flush=True)

    # A sender's TCP_USER_TIMEOUT fires while b is paused.
    d, g = connect()
    ask(d, g)
    d.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 1000)
    ctl("pause b")
    t0 = time.monotonic()
    d.sendall(b"?\n")
    try:
        line = g.readline()
        fail(f"read while b is paused: {line!r}")
    except OSError as e:
        if e.errno != errno.ETIMEDOUT:
            fail(f"read while b is paused: {e}")
    gave = time.monotonic() - t0
    ctl("resume b")
    print(f"ok sender: TCP_USER_TIMEOUT=1000 gave up after {int(gave * 1000)} ms with ETIMEDOUT",
          flush=True)
    a = ask(c, f)
    print("ok after: the first connection still answers", flush=True)

    # A paused machine can be killed; a pause of a machine that is down is EAGAIN.
    ctl("pause b")
    ctl("kill b")
    ctl("pause b", errno.EAGAIN)
    ctl("start b")
    c, f = connect()
    ask(c, f)
    print("ok kill: a paused machine killed and started again; a pause while down EAGAIN", flush=True)


def seed(seconds):
    c, f = connect()
    worst = 0.0
    n = 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        t0 = time.monotonic()
        ask(c, f)
        worst = max(worst, time.monotonic() - t0)
        n += 1
        time.sleep(0.5)
    print(f"ok seed: {n} answers, the longest wait {int(worst * 1000)} ms", flush=True)


def stuck():
    c, f = connect()
    ask(c, f)
    ctl("pause b")
    # Nothing sent and not acknowledged: no give-up clock runs, only b could end this wait.
    c.recv(1)


if __name__ == "__main__":
    if sys.argv[1] == "b":
        machine()
    elif sys.argv[2] == "script":
        script()
    elif sys.argv[2] == "seed":
        seed(float(sys.argv[3]))
    else:
        stuck()
