#!/usr/bin/env python3
"""What one machine can see of another.

    iso.py machine     (machine b) leave marks in its disk, /tmp, /dev/shm and System V shared
                    memory, listen on :7000 and on its loopback :7001, and answer each
                    connection on :7000 with a report of what it sees
    iso.py main   leave its own marks, read b's report, check what each side can reach

Prints one line per check; exits 1 at the first that does not hold.
"""
import ctypes
import errno
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

import patina

libc = ctypes.CDLL(None, use_errno=True)
ABSTRACT = []  # sockets kept open for the run
KEY = 0x5157


def call(f, *a):
    r = f(*a)
    return 0 if r >= 0 else ctypes.get_errno()


def mark(name):
    for d in (os.getcwd(), "/tmp", "/dev/shm"):
        open(os.path.join(d, name), "w").close()
    call(libc.shmget, KEY if name == "b" else KEY + 1, 4096, 0o1600)


def seen(name):
    return [d for d in (os.getcwd(), "/tmp", "/dev/shm") if os.path.exists(os.path.join(d, name))]


def err(f):
    try:
        f()
        return 0
    except OSError as e:
        return e.errno


def abstract(listen_as):
    """Bind the abstract name `\0iso` (every machine may: each has its own), listen on
    `listen_as`, and try the other side's: (bind errno, the name read back, connect errno to
    the other's name, connect errno to its own)."""
    s = socket.socket(socket.AF_UNIX)
    e = err(lambda: s.bind("\0iso"))
    name = s.getsockname() if e == 0 else None
    lis = socket.socket(socket.AF_UNIX)
    lis.bind(listen_as)
    lis.listen()
    ABSTRACT.append((s, lis))
    other = "\0iso-d" if listen_as == "\0iso-b" else "\0iso-b"
    c = socket.socket(socket.AF_UNIX)
    theirs = err(lambda: c.connect(other))
    c.close()
    c = socket.socket(socket.AF_UNIX)
    mine = err(lambda: c.connect(listen_as))
    c.close()
    return e, name if name is None else name.decode() if isinstance(name, bytes) else name, theirs, mine


def names():
    """Names the kernel hands back within one machine, each with its prefix taken off:
    (recvfrom's source, recvmsg's source, an autobind's length)."""
    def n(x):
        return x.decode() if isinstance(x, bytes) else x
    a = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    a.bind("\0iso-x")
    b = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    b.bind("\0iso-y")
    b.sendto(b"1", "\0iso-x")
    _, src = a.recvfrom(10)
    b.sendmsg([b"2"], [], 0, "\0iso-x")
    _, _, _, src2 = a.recvmsg(10)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.bind("")
    auto = c.getsockname()
    for s in (a, b, c):
        s.close()
    return n(src), n(src2), len(auto)


def sink():
    """Accept on :7004 and read what comes, for as long as it comes."""
    s = socket.socket()
    s.bind(("0.0.0.0", 7004))
    s.listen()
    while True:
        c, _ = s.accept()
        threading.Thread(target=lambda c=c: [None for _ in iter(lambda: c.recv(65536), b"")], daemon=True).start()


def udp_echo():
    """Answer each datagram on :7002 with the address it came from."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 7002))
    while True:
        d, peer = u.recvfrom(100)
        u.sendto(json.dumps([d.decode(), peer[0]]).encode(), peer)


def state():
    """The process state a machine's first process inherits, as main's has it."""
    import resource
    um = os.umask(0)
    os.umask(um)
    return {
        "umask": um,
        "limits": [resource.getrlimit(r) for r in range(16)],
        "mask": sorted(signal.pthread_sigmask(signal.SIG_BLOCK, [])),
        "ignored": [s for s in range(1, 32) if s not in (9, 19) and signal.getsignal(s) == signal.SIG_IGN],
        "nice": os.getpriority(os.PRIO_PROCESS, 0),
        "cpus": len(os.sched_getaffinity(0)),
        "fds": sorted(os.listdir("/proc/self/fd")),
        "uid": (os.getuid(), os.getgid(), os.getgroups()),
        "env": sorted(k for k in os.environ if k not in ("HOME", "PATINA_MACHINE")),
    }


def report(peer):
    ctl = subprocess.run(["patina", "ctl", "heal"], capture_output=True, text=True)
    return {
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "own": seen("b"),
        "main": seen("d"),
        "shm_driver": call(libc.shmget, KEY + 1, 0, 0),
        "control": err(lambda: patina.control("partition main b")),
        "ctl_exit": ctl.returncode,
        "ctl_err": ctl.stderr.strip(),
        "abstract": ABSTRACT_B,
        "abstract_d": err(lambda: socket.socket(socket.AF_UNIX).connect("\0iso-d")),
        "sethostname": call(libc.sethostname, b"x", 1),
        "peer": peer[0],
        "state": START,
        "machine": os.environ.get("PATINA_MACHINE"),
    }


def machine():
    global ABSTRACT_B
    mark("b")
    ABSTRACT_B = abstract("\0iso-b")
    threading.Thread(target=udp_echo, daemon=True).start()
    threading.Thread(target=sink, daemon=True).start()
    lo = socket.socket()
    lo.bind(("127.0.0.1", 7001))
    lo.listen()
    s = socket.socket()
    s.bind(("0.0.0.0", 7000))
    s.listen()
    while True:
        c, peer = s.accept()
        c.sendall(json.dumps(report(peer)).encode() + b"\n")
        c.close()


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        sys.exit(1)


def connect(addr, timeout=None):
    c = socket.socket()
    c.settimeout(timeout)
    try:
        c.connect(addr)
        return c
    except OSError as e:
        c.close()
        return e.errno if e.errno is not None else "timeout"


def ping(u, tries):
    """A datagram to b's echo, sent up to `tries` times a second apart: (answer, source), or
    None."""
    u.settimeout(1)
    for _ in range(tries):
        u.sendto(b"ping", ("b", 7002))
        try:
            return u.recvfrom(100)
        except socket.timeout:
            continue
    return None


def main():
    mark("d")
    # Bound before b reports, so that b's connect to it is refused only because names are
    # per machine.
    own = abstract("\0iso-d")
    while True:
        c = connect(("b", 7000))
        if not isinstance(c, int):
            break
        time.sleep(0.05)
    local = c.getsockname()[0]
    r = json.loads(c.makefile().readline())
    c.close()
    check(socket.gethostname() == "main" and r["hostname"] == "b", "each machine has its own hostname")
    check(r["own"] == [r["cwd"], "/tmp", "/dev/shm"] and r["main"] == [],
          "b sees its own disk, /tmp and /dev/shm, not main's")
    check(seen("b") == [] and seen("d") == [os.getcwd(), "/tmp", "/dev/shm"],
          "main sees its own, not b's")
    check(r["shm_driver"] == errno.ENOENT and call(libc.shmget, KEY, 0, 0) == errno.ENOENT,
          "System V shared memory is per machine")
    check(local == "10.0.0.1" and r["peer"] == "10.0.0.1", "addresses: main is 10.0.0.1 at both ends")
    check(connect(("10.0.0.2", 7001)) == errno.ECONNREFUSED, "b's loopback listener is not on its address")
    check(connect(("127.0.0.1", 7001)) == errno.ECONNREFUSED and connect(("127.0.0.1", 7000)) == errno.ECONNREFUSED,
          "main's loopback is its own")
    mine = json.loads(json.dumps(START))
    diff = sorted((k, mine[k], r["state"][k]) for k in mine if mine[k] != r["state"][k])
    check(diff == [], f"b's first process inherits main's process state (differs: {diff})")
    check(os.environ.get("PATINA_MACHINE") == "main" and r["machine"] == "b", "PATINA_MACHINE names the machine")
    pid = r["pid"]
    check(err(lambda: os.kill(pid, 0)) == errno.ESRCH and err(lambda: os.kill(pid, signal.SIGKILL)) == errno.ESRCH,
          "b's processes are not main's to signal (ESRCH)")
    check(not os.path.exists(f"/proc/{pid}"), "b's processes are not in main's /proc")
    check(r["control"] == errno.EPERM and r["ctl_exit"] != 0 and "main" in r["ctl_err"],
          "b may not act on the network (EPERM)")
    check(r["abstract"][:2] == [0, "\0iso"] and own[:2] == (0, "\0iso"),
          "abstract AF_UNIX names are per machine: both bind \\0iso and read it back as given")
    check(r["abstract_d"] == errno.ECONNREFUSED and r["abstract"][3] == 0 and own[3] == 0,
          "a machine reaches its own abstract names, not another's")
    src, src2, auto = names()
    check(src == "\0iso-y" and src2 == "\0iso-y" and auto == 6,
          "names read back (recvfrom, recvmsg, an autobind) show no prefix")
    check(err(lambda: os.getsid(pid)) == errno.ESRCH and err(lambda: os.getpgid(pid)) == errno.ESRCH,
          "getsid and getpgid do not find b's processes (ESRCH)")
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 7003))
    d, src = ping(u, 100)
    check(json.loads(d) == ["ping", "10.0.0.1"] and src == ("10.0.0.2", 7002),
          "UDP between machines: b sees main's address, main sees b's")
    check(r["sethostname"] == errno.EPERM, "b has no capability to change its view")

    patina.control("partition main b")
    check(connect(("b", 7000), timeout=5) == "timeout", "a cut: a connect to b does not complete")
    check(ping(u, 3) is None, "a cut: a datagram to b is lost")
    patina.control("heal")
    c = connect(("b", 7000), timeout=60)
    check(not isinstance(c, (int, str)), "healed: a connect to b completes")
    c.close()
    check(ping(u, 100) is not None, "healed: datagrams reach b again")

    # A socket's own limits across a cut: TCP_SYNCNT 2 gives up at 7 s (1 + 2 + 4), and
    # TCP_USER_TIMEOUT 2000 fails a send whose data the cut held for 2 s.
    patina.control("partition main b")
    c = socket.socket()
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 2)
    t = time.monotonic()
    e = err(lambda: c.connect(("b", 7000)))
    took = time.monotonic() - t
    c.close()
    check(e == errno.ETIMEDOUT and 6.5 < took < 8, f"TCP_SYNCNT 2: ETIMEDOUT after {took:.1f} s")
    patina.control("heal")
    c = connect(("b", 7004), timeout=60)
    c.settimeout(None)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 2000)
    patina.control("partition --from main --to b")
    c.send(b"x")
    time.sleep(5)
    e = err(lambda: c.send(b"y"))
    c.close()
    patina.control("heal")
    check(e == errno.ETIMEDOUT, f"TCP_USER_TIMEOUT 2000: a held send fails ETIMEDOUT ({e})")


if __name__ == "__main__":
    START = state()
    {"machine": machine, "main": main}[sys.argv[1]]()
