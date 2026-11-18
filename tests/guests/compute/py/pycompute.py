"""Python programs for compute points (`python3 -m patina pycompute.py MODE ...`).

    cache [KEYS]   two threads fill a cache with check-then-act and no system call between the
                   check and the act; exit 1 when a key was built twice
    timer MS       a loop with no system call, cut by an ITIMER_REAL of MS (virtual) ms; prints
                   the passes it made and the virtual time its handler saw
    oneline MS     the same timer cutting a one-line loop and a comprehension, each inside a
                   try (no line starts while they run: the hook's jumps get the signal)
    watchdog MS    a loop that stops when a threading.Timer of MS ms sets a flag
    cpu N          two threads each loop N passes with no system call; prints how many times
                   the progress marks they leave alternate between the two
    burn N         two threads each loop N passes and allocate nothing (no system call at all)
    loop N         one tight loop of N passes (for costs)
    mix N          plain Python of every kind, N rounds: a word count, a sort with a key, method
                   calls and branches (for costs)
"""
import signal
import sys
import threading
import time


def cache(keys):
    table = {}
    built = []

    def build(k):
        return [k] * 3

    def get(k):
        if k not in table:
            v = build(k)
            table[k] = v
            built.append(k)
        return table[k]

    go = threading.Barrier(2)

    def worker():
        go.wait()
        for k in range(keys):
            get(k)

    ts = [threading.Thread(target=worker) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if len(built) != keys:
        print(f"built {len(built)} values for {keys} keys")
        sys.exit(1)
    print(f"built {keys} values for {keys} keys")


class Stop(Exception):
    pass


def timer(ms):
    seen = []

    def handler(signo, frame):
        seen.append(time.monotonic_ns() - t0)
        raise Stop

    signal.signal(signal.SIGALRM, handler)
    t0 = time.monotonic_ns()
    signal.setitimer(signal.ITIMER_REAL, ms / 1000)
    n = 0
    try:
        while n < 20_000_000:
            n += 1
    except Stop:
        print(f"timer fired after {n} passes, handler_ns={seen[0]}")
        return
    print(f"timer did not fire: {n} passes")


def oneline(ms):
    def handler(signo, frame):
        raise Stop

    signal.signal(signal.SIGALRM, handler)
    n = 0
    signal.setitimer(signal.ITIMER_REAL, ms / 1000)
    try:
        while n < 50_000_000: n += 1  # noqa: E701
        print(f"one-line loop: the timer did not fire: {n} passes")
    except Stop:
        print("one-line loop: Stop caught")
    signal.setitimer(signal.ITIMER_REAL, ms / 1000)
    try:
        print(f"comprehension: the timer did not fire: {len([i for i in range(50_000_000)])}")
    except Stop:
        print("comprehension: Stop caught")


def watchdog(ms):
    stop = []
    t = threading.Timer(ms / 1000, stop.append, (True,))
    t.start()
    n = 0
    while not stop and n < 20_000_000:
        n += 1
    t.cancel()
    print(f"watchdog {'fired' if stop else 'did not fire'} after {n} passes")


def cpu(n):
    marks = []

    def work(name):
        x = 0
        for i in range(n):
            x += i
            if i % 1000 == 0:
                marks.append(name)

    ts = [threading.Thread(target=work, args=(c,)) for c in "ab"]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    alt = sum(1 for a, b in zip(marks, marks[1:]) if a != b)
    print(f"cpu: {len(marks)} marks, {alt} alternations")


def burn(n):
    done = []

    def work(name):
        x = 0
        for i in range(n):
            x += i
        done.append(name)

    ts = [threading.Thread(target=work, args=(c,)) for c in "ab"]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print(f"burn: {' then '.join(done)} finished")


def loop(n):
    x = 0
    for i in range(n):
        x += i
    print(f"loop {n}: {x}")


def mix(n):
    import random

    r = random.Random(2)
    words = ["".join(r.choice("abcdefgh") for _ in range(r.randint(2, 6))) for _ in range(6000 * n)]
    counts = {}
    for w in words:
        counts[w] = counts.get(w, 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]

    class Acct:
        def __init__(self):
            self.bal = 100

        def move(self, other, amt):
            if self.bal >= amt:
                self.bal -= amt
                other.bal += amt
                return True
            return False

    accts = [Acct() for _ in range(50)]
    ok = 0
    for _ in range(15000 * n):
        a, b = r.sample(accts, 2)
        ok += a.move(b, r.randint(1, 30))
    print(f"mix {n}: {top} {ok} {sum(a.bal for a in accts)}")


mode, arg = sys.argv[1], int(sys.argv[2])
modes = {"cache": cache, "timer": timer, "oneline": oneline, "watchdog": watchdog, "cpu": cpu,
         "burn": burn, "loop": loop, "mix": mix}
modes[mode](arg)
