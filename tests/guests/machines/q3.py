#!/usr/bin/env python3
"""A replicated register store on three machines (a primary and two backups), and its main.

    q3.py NAME [BUG...]   NAME is n1, n2 or n3: serve clients on :7000 and peers on :7100
    q3.py main SECONDS  write and read through whichever machine answers, check every answer

View `v` has primary `MACHINES[v % 3]`. The primary appends each SET to its log, sends the whole
log to both backups (`SYNC`) and answers `OK` once one of them (a quorum of two with itself)
has taken it; it answers reads while it holds a lease, renewed by a backup's answer to its
heartbeat. A backup that has not heard from its primary for `GRACE` (longer than the lease)
asks the other machines to move to the next view it would lead; one that grants hands over its
log and takes no `SYNC` from a lower view after that, so an old primary can get no quorum (the
fence). The new primary keeps the longer of the two logs (by the view of its last entry, then
its length) and syncs it to both. Each machine keeps its view and log in its disk, synced
before it answers (`state.json`), and reads them back when it starts again.

Planted bugs (any of them as extra words):

    early       the primary answers OK before any backup has the update
    nolease     the primary answers reads without checking its lease
    nofence     a primary whose backups do not answer answers OK on its own
    amnesia     a machine keeps its view in its disk but not its log (it restarts empty)
    nosync      a machine answers without syncing its disk (a machine crash may lose what
                it acknowledged)

Main sends each request to the machines in turn, following a redirect to the primary a machine
names. It is the only writer, with increasing values, so a read must return the last value
acknowledged for its key or one of the writes whose outcome it does not know. Every answer
carries the view it was given in. Findings (`FAIL: LABEL: detail`, exit 1):

    split brain     an acknowledgement in a view below one already acknowledged
    stale read      a read older than a value already seen, from a primary of an older view (or
                    after reading an older primary's value that no later view kept)
    lost write      a read older than a value already acknowledged, from the newest primary
"""
import json
import os
import random
import socket
import sys
import threading
import time

MACHINES = ["n1", "n2", "n3"]
LEASE = 0.5
GRACE = 1.0
BEAT = 0.1
RPC = 0.3


def now():
    return time.monotonic()


def rpc(host, line, timeout=RPC):
    """One request on a fresh connection: its answer line, or None."""
    try:
        c = socket.create_connection((host, 7100), timeout=timeout)
    except OSError:
        return None
    try:
        c.settimeout(timeout)
        c.sendall((line + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            d = c.recv(65536)
            if not d:
                return None
            buf += d
        return buf.split(b"\n", 1)[0].decode()
    except OSError:
        return None
    finally:
        c.close()


def lines(conn):
    buf = b""
    while True:
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode()
        try:
            d = conn.recv(65536)
        except OSError:
            return
        if not d:
            return
        buf += d


def serve(port, handle):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        try:
            c, _ = s.accept()
        except OSError:  # a connection reset before it was accepted (ECONNABORTED)
            continue
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def rank(log):
    return (log[-1][0], len(log)) if log else (-1, 0)


class Machine:
    def __init__(self, me, bugs):
        self.me, self.bugs = me, bugs
        self.others = [n for n in MACHINES if n != me]
        self.lock = threading.Lock()
        self.view, self.log, self.normal = 0, [], True
        self.heard = now()
        # When a backup whose election failed asks again: its own clock, apart from `heard`
        # (a machine trying to lead still grants a higher view when its primary is quiet; one
        # that counted its own tries as hearing from a primary granted none, and two such
        # machines waiting on a primary that forgot its view never elected one).
        self.retry = 0.0
        self.lease = 0.0
        self.load()

    # Disk state: the view, and (unless the machine forgets it) the log.
    def load(self):
        try:
            with open("state.json") as f:
                s = json.load(f)
        except (OSError, ValueError):
            return
        # It takes up its role in its view again (with amnesia, as if it still had its log).
        self.view = s["view"]
        self.log = [] if "amnesia" in self.bugs else [tuple(e) for e in s["log"]]

    def save(self):
        # Durable before the machine answers: the new file synced, renamed, the directory synced
        # (without `nosync`, which a machine crash can make lose what it acknowledged).
        s = {"view": self.view, "log": [] if "amnesia" in self.bugs else self.log}
        with open("state.json.tmp", "w") as f:
            json.dump(s, f)
            if "nosync" not in self.bugs:
                f.flush()
                os.fsync(f.fileno())
        os.replace("state.json.tmp", "state.json")
        if "nosync" not in self.bugs:
            d = os.open(".", os.O_RDONLY)
            os.fsync(d)
            os.close(d)

    def primary(self, v=None):
        return MACHINES[(self.view if v is None else v) % 3]

    def leading(self):
        return self.primary() == self.me and self.normal

    def value(self, k):
        for e in reversed(self.log):
            if e[1] == k:
                return e[2]
        return "-"

    # Peers.
    def peer(self, c):
        for line in lines(c):
            w = line.split(" ", 2)
            with self.lock:
                if w[0] == "SYNC":
                    v, log = int(w[1]), [tuple(e) for e in json.loads(w[2])]
                    if v < self.view or (v == self.view and self.primary() == self.me):
                        out = f"NACK {self.view}"
                    else:
                        # In one view the primary's log only grows: an older SYNC that arrives
                        # late does not shorten it.
                        if v > self.view or len(log) >= len(self.log):
                            self.log = log
                        self.view, self.normal = v, True
                        self.heard = now()
                        self.save()
                        out = f"ACK {v}"
                elif w[0] == "VOTE":
                    v = int(w[1])
                    quiet = now() > self.heard + GRACE and now() > self.lease
                    if v > self.view and quiet:
                        self.view, self.normal = v, False
                        self.heard = now()
                        self.save()
                        out = "GRANT " + json.dumps(self.log)
                    else:
                        out = f"DENY {self.view}"
                else:
                    out = "?"
            try:
                c.sendall((out + "\n").encode())
            except OSError:
                return

    def sync(self, v, log):
        """Send the log to both backups at once: how many took it in view `v`. A backup in a
        higher view makes this machine a backup in that view."""
        got, higher = [], []
        msg = f"SYNC {v} {json.dumps(log)}"

        def one(n):
            a = rpc(n, msg)
            if a == f"ACK {v}":
                got.append(n)
            elif a and a.startswith("NACK "):
                higher.append(int(a[5:]))

        ts = [threading.Thread(target=one, args=(n,)) for n in self.others]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        if higher:
            with self.lock:
                if max(higher) > self.view:
                    self.view, self.normal, self.lease = max(higher), True, 0.0
                    self.heard = now()
                    self.save()
        return len(got)

    def beat(self):
        while True:
            time.sleep(BEAT)
            with self.lock:
                lead, v, log = self.leading(), self.view, list(self.log)
            if lead:
                sent = now()
                if self.sync(v, log) > 0:
                    with self.lock:
                        if self.view == v:
                            self.lease = sent + LEASE
            else:
                self.watch()

    def watch(self):
        """A backup that has not heard from its primary asks for the next view it leads."""
        with self.lock:
            if now() <= self.heard + GRACE or now() < self.retry:
                return
            v = self.view + 1
            while self.primary(v) != self.me:
                v += 1
        for n in self.others:
            a = rpc(n, f"VOTE {v}")
            if a and a.startswith("GRANT "):
                theirs = [tuple(e) for e in json.loads(a[6:])]
                with self.lock:
                    if self.view >= v:
                        return
                    if rank(theirs) > rank(self.log):
                        self.log = theirs
                    self.view, self.normal, self.lease = v, True, 0.0
                    self.heard = now()
                    self.save()
                    log = list(self.log)
                self.sync(v, log)
                return
        with self.lock:
            # Try again after another grace period, a random part longer: two candidates
            # do not keep asking at once.
            self.retry = now() + GRACE * (1 + random.random())

    # Clients.
    def client(self, c):
        for line in lines(c):
            w = line.split()
            with self.lock:
                lead, v = self.leading(), self.view
                if not lead:
                    out = f"REDIRECT {self.primary()} {v}"
                elif w[0] == "GET":
                    if "nolease" in self.bugs or now() < self.lease:
                        out = f"VALUE {self.value(w[1])} {v}"
                    else:
                        out = f"REDIRECT {self.me} {v}"
                else:
                    self.log.append((v, w[1], w[2]))
                    self.save()
                    log = list(self.log)
            if lead and w[0] == "SET":
                if "early" in self.bugs:
                    threading.Thread(target=self.sync, args=(v, log), daemon=True).start()
                    out = f"OK {v}"
                else:
                    n = self.sync(v, log)
                    with self.lock:
                        still = self.view == v
                    if n > 0 and still:
                        out = f"OK {v}"
                    elif "nofence" in self.bugs and still:
                        out = f"OK {v}"
                    else:
                        out = f"UNKNOWN {v}"
            try:
                c.sendall((out + "\n").encode())
            except OSError:
                return

    def run(self):
        threading.Thread(target=serve, args=(7100, self.peer), daemon=True).start()
        threading.Thread(target=self.beat, daemon=True).start()
        serve(7000, self.client)


def fail(label, why):
    print(f"FAIL: {label}: {why}", flush=True)
    sys.exit(1)


class Main:
    def __init__(self):
        self.acked = {}  # key -> last value acknowledged (or read)
        self.source = {}  # key -> how that value was seen: ("ack" or "read", view)
        self.unknown = {}  # key -> values written with no answer
        self.top = -1  # the highest view an acknowledgement came in
        self.n = 0
        self.oks = self.reads = 0

    def ask(self, line):
        """Send to the next machine, following one redirect: (answer words) or None."""
        host = MACHINES[self.n % 3]
        self.n += 1
        for _ in range(2):
            try:
                c = socket.create_connection((host, 7000), timeout=1.0)
            except OSError:
                return None
            try:
                c.settimeout(2.0)
                c.sendall((line + "\n").encode())
                a = next(lines(c), None)
            except OSError:
                a = None
            finally:
                c.close()
            if a is None:
                return None
            w = a.split()
            if w[0] != "REDIRECT" or w[1] == host:
                return w
            host = w[1]
        return None

    def check(self, k, got, v):
        last = self.acked.get(k, 0)
        if got == "-":
            got = 0
        got = int(got)
        if got >= last and (got == last or got in self.unknown.get(k, ())):
            if got != last:
                self.source[k] = ("read", v)
            self.acked[k] = got
            self.unknown[k] = {x for x in self.unknown.get(k, ()) if x > got}
            return
        # A read of an older view's primary, or one after a read of an older primary's value
        # that no later view kept, is stale; otherwise the newest primary lost a write.
        src = self.source.get(k, ("ack", self.top))
        stale = v < self.top or (src[0] == "read" and src[1] < v)
        how = f"{src[0]} in view {src[1]}"
        fail("stale read" if stale else "lost write",
             f"{k} read {got} in view {v}; {last} was seen before ({how}; views up to {self.top})")

    def run(self, seconds):
        end = now() + seconds
        val = 0
        i = 0
        while now() < end:
            k = f"k{i % 3}"
            i += 1
            if i % 2:
                val += 1
                a = self.ask(f"SET {k} {val}")
                if a and a[0] == "OK":
                    v = int(a[1])
                    if v < self.top:
                        fail("split brain", f"SET {k} {val} acknowledged in view {v} after view {self.top}")
                    self.top = v
                    self.acked[k] = val
                    self.source[k] = ("ack", v)
                    self.unknown[k] = set()
                    self.oks += 1
                else:
                    self.unknown.setdefault(k, set()).add(val)
            else:
                a = self.ask(f"GET {k}")
                if a and a[0] == "VALUE":
                    self.check(k, a[1], int(a[2]))
                    self.reads += 1
            time.sleep(0.05)
        # The end: every acknowledged write is read back from a primary.
        for k in sorted(self.acked):
            for _ in range(200):
                a = self.ask(f"GET {k}")
                if a and a[0] == "VALUE":
                    self.check(k, a[1], int(a[2]))
                    break
                time.sleep(0.1)
            else:
                fail("no primary", f"no read of {k} answered at the end")
        print(f"ok: {self.oks} writes acknowledged, {self.reads} reads checked, views up to {self.top}",
              flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "main":
        Main().run(float(sys.argv[2]))
    else:
        Machine(sys.argv[1], sys.argv[2:]).run()
