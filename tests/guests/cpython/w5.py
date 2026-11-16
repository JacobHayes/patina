"""W5 cpython: run by the stock /usr/bin/python3 with no flags.

    python3 w5.py [local|net|all]   (default all; "net" adds a TCP echo over loopback)

Lines starting with "v " are the values the runtimes checks compare across runs and seeds.
Lines starting with "~ " depend on the schedule, time or PIDs. File errors (OSError) are
printed as "oserror ..." lines and counted; the program still finishes. Last line: "done".
"""
import hashlib
import os
import queue
import random
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def values():
    print("v random", random.random())
    print("v hash", hash("x"))
    print("v id", id(object()))
    print("v urandom", os.urandom(4).hex())
    print("v time", time.time())
    print("v pid", os.getpid())
    tid = []
    t = threading.Thread(target=lambda: tid.append(threading.get_native_id()))
    t.start()
    t.join()
    print("v native_id main", threading.get_native_id(), "thread", tid[0])
    d = tempfile.mkdtemp()
    print("v mkdtemp", d)
    os.rmdir(d)
    print("v uuid4", uuid.uuid4())


def threads():
    lock = threading.Lock()
    cond = threading.Condition(lock)
    q = queue.Queue()
    state = {"n": 0, "order": []}

    def worker(i):
        h = hashlib.sha256(str(i).encode())
        for _ in range(2000):
            h.update(h.digest())
        with cond:
            state["n"] += 1
            state["order"].append(i)
            cond.notify_all()
        q.put((i, h.hexdigest()[:8]))

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    with cond:
        while state["n"] < 8:
            cond.wait(timeout=30)
    for t in ts:
        t.join()
    res = sorted(q.get() for _ in range(8))
    print("threads:", " ".join(h for _, h in res))
    print("~ thread order", state["order"])


def files(base):
    errors = []
    try:
        d = tempfile.mkdtemp(dir=base, prefix="w5-")
    except OSError as e:
        print("oserror mkdtemp", type(e).__name__, e.errno)
        return 1
    for i in range(10):
        p = os.path.join(d, "f%d" % i)
        try:
            with open(p + ".tmp", "w") as f:
                for k in range(20):
                    f.write("file %d line %d\n" % (i, k))
                f.flush()
                os.fsync(f.fileno())
            os.rename(p + ".tmp", p)
        except OSError as e:
            errors.append("oserror file %d %s errno=%s" % (i, type(e).__name__, e.errno))
    h = hashlib.sha256()
    try:
        for n in sorted(os.listdir(d)):
            with open(os.path.join(d, n), "rb") as f:
                h.update(n.encode() + f.read())
    except OSError as e:
        errors.append("oserror readback %s errno=%s" % (type(e).__name__, e.errno))
    for e in errors:
        print(e)
    print("files: %d errors, digest %s" % (len(errors), h.hexdigest()[:16]))
    return d


def db(d):
    try:
        con = sqlite3.connect(os.path.join(d, "t.db"), check_same_thread=False, timeout=30)
        con.execute("create table t (k integer primary key, v text)")
        lock = threading.Lock()

        def ins(base):
            for k in range(base, base + 50):
                with lock:
                    con.execute("insert into t values (?, ?)", (k, "v%d" % k))
                    con.commit()

        ts = [threading.Thread(target=ins, args=(b,)) for b in (0, 1000)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        n, s = con.execute("select count(*), sum(k) from t").fetchone()
        con.close()
        print("sqlite: %d rows, key sum %d" % (n, s or 0))
    except (OSError, sqlite3.Error) as e:
        print("oserror sqlite", type(e).__name__)


def procs():
    r = subprocess.run(["sort", "-n"], input=b"30\n4\n200\n17\n", capture_output=True)
    print("subprocess sort:", r.stdout.decode().split(), r.returncode)
    r = subprocess.run(["sh", "-c", "exit 3"])
    print("subprocess exit:", r.returncode)
    p = subprocess.Popen(["seq", "1", "5"], stdout=subprocess.PIPE)
    out, _ = p.communicate()
    print("subprocess seq:", out.decode().split())


def sockets(net):
    a, b = socket.socketpair()

    def echo(s):
        while True:
            m = s.recv(100)
            if not m:
                break
            s.sendall(m.upper())
        s.close()

    t = threading.Thread(target=echo, args=(b,))
    t.start()
    got = []
    for w in ("one", "two", "three"):
        a.sendall(w.encode())
        got.append(a.recv(100).decode())
    a.close()
    t.join()
    print("socketpair echo:", got)
    if not net:
        return
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    # A connection reset by the peer (net-reset-permille) is reported, not fatal: the server
    # takes 4 connection attempts, the client reads each reply in full (a stream may deliver
    # it in pieces, net-chunk-max).
    srv.settimeout(30)

    def serve():
        for _ in range(4):
            try:
                c, _ = srv.accept()
                c.settimeout(30)
                echo(c)
            except OSError as e:
                print("tcp server error:", type(e).__name__)
        srv.close()

    t = threading.Thread(target=serve)
    t.start()
    got = []
    for i in range(4):
        m = b"msg%d" % i
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=10)
            c.sendall(m)
            r = b""
            while len(r) < len(m):
                k = c.recv(100)
                if not k:
                    break
                r += k
            got.append(r.decode())
            c.close()
        except OSError as e:
            print("tcp client %d error: %s" % (i, type(e).__name__))
    t.join()
    print("tcp echo:", got)


def sleeps():
    t0 = time.monotonic()
    time.sleep(1.5)
    dt = time.monotonic() - t0
    print("sleep 1.5: elapsed >= 1.5:", dt >= 1.5)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    values()
    threads()
    d = files(os.getcwd())
    if isinstance(d, str):
        db(d)
    procs()
    sockets(mode in ("net", "all"))
    sleeps()
    print("done")


main()
