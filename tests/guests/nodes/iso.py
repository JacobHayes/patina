#!/usr/bin/env python3
"""What one node can see of another.

    iso.py node     (node b) leave marks in its work tree, /tmp, /dev/shm and System V shared
                    memory, listen on :7000 and on its loopback :7001, and answer each
                    connection on :7000 with a report of what it sees
    iso.py driver   leave its own marks, read b's report, check what each side can reach

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
import time

import patina

libc = ctypes.CDLL(None, use_errno=True)
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


def abstract():
    s = socket.socket(socket.AF_UNIX)
    try:
        return err(lambda: s.bind("\0iso"))
    finally:
        s.close()


def state():
    """The process state a node's first process inherits, as the driver's has it."""
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
        "env": sorted(k for k in os.environ if k not in ("HOME", "PATINA_NODE")),
    }


def report(peer):
    ctl = subprocess.run(["patina", "ctl", "net", "heal"], capture_output=True, text=True)
    return {
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "own": seen("b"),
        "driver": seen("d"),
        "shm_driver": call(libc.shmget, KEY + 1, 0, 0),
        "control": err(lambda: patina.control("net cut driver b")),
        "ctl_exit": ctl.returncode,
        "ctl_err": ctl.stderr.strip(),
        "abstract": abstract(),
        "sethostname": call(libc.sethostname, b"x", 1),
        "peer": peer[0],
        "state": START,
        "node": os.environ.get("PATINA_NODE"),
    }


def node():
    mark("b")
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


def driver():
    mark("d")
    while True:
        c = connect(("b", 7000))
        if not isinstance(c, int):
            break
        time.sleep(0.05)
    local = c.getsockname()[0]
    r = json.loads(c.makefile().readline())
    c.close()
    check(socket.gethostname() == "driver" and r["hostname"] == "b", "each node has its own hostname")
    check(r["own"] == [r["cwd"], "/tmp", "/dev/shm"] and r["driver"] == [],
          "b sees its own work tree, /tmp and /dev/shm, not the driver's")
    check(seen("b") == [] and seen("d") == [os.getcwd(), "/tmp", "/dev/shm"],
          "the driver sees its own, not b's")
    check(r["shm_driver"] == errno.ENOENT and call(libc.shmget, KEY, 0, 0) == errno.ENOENT,
          "System V shared memory is per node")
    check(local == "10.0.0.1" and r["peer"] == "10.0.0.1", "addresses: the driver is 10.0.0.1 at both ends")
    check(connect(("10.0.0.2", 7001)) == errno.ECONNREFUSED, "b's loopback listener is not on its address")
    check(connect(("127.0.0.1", 7001)) == errno.ECONNREFUSED and connect(("127.0.0.1", 7000)) == errno.ECONNREFUSED,
          "the driver's loopback is its own")
    mine = json.loads(json.dumps(START))
    diff = sorted((k, mine[k], r["state"][k]) for k in mine if mine[k] != r["state"][k])
    check(diff == [], f"b's first process inherits the driver's process state (differs: {diff})")
    check(os.environ.get("PATINA_NODE") == "driver" and r["node"] == "b", "PATINA_NODE names the node")
    pid = r["pid"]
    check(err(lambda: os.kill(pid, 0)) == errno.ESRCH and err(lambda: os.kill(pid, signal.SIGKILL)) == errno.ESRCH,
          "b's processes are not the driver's to signal (ESRCH)")
    check(not os.path.exists(f"/proc/{pid}"), "b's processes are not in the driver's /proc")
    check(r["control"] == errno.EPERM and r["ctl_exit"] != 0 and "driver" in r["ctl_err"],
          "b may not act on the network (EPERM)")
    check(r["abstract"] == errno.EOPNOTSUPP and abstract() == errno.EOPNOTSUPP,
          "abstract AF_UNIX names are refused with nodes")
    check(r["sethostname"] == errno.EPERM, "b has no capability to change its view")

    patina.control("net cut driver b")
    check(connect(("b", 7000), timeout=5) == "timeout", "a cut: a connect to b does not complete")
    patina.control("net heal")
    c = connect(("b", 7000), timeout=60)
    check(not isinstance(c, (int, str)), "healed: a connect to b completes")
    c.close()


if __name__ == "__main__":
    START = state()
    {"node": node, "driver": driver}[sys.argv[1]]()
