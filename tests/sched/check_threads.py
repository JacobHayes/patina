"""Check the printed results of a the scheduler guest: check_threads.py GUEST STDOUT."""
import collections, re, sys

g, path = sys.argv[1], sys.argv[2]
out = open(path).read()
lines = {l.split()[0]: l.split()[1:] for l in out.splitlines() if l.strip()}

def need(cond, what):
    if not cond:
        print(f"{g}: {what}\n{out}")
        sys.exit(1)

if g == "c-threads":
    need(lines["counter"] == ["16000"], "counter")
    need(lines["pingpong"] == ["400", "rounds", "alternating", "1"], "pingpong")
    need(lines["barrier"] == ["phases", "5", "ok", "1"], "barrier")
    need(lines["detached"] == ["42"], "detached")
    rc, ns = lines["nanosleep"][1], int(lines["nanosleep"][3])
    need(rc == "0" and 250_000_000 <= ns < 251_000_000, "nanosleep")
    rc, ns = lines["timedwait"][1], int(lines["timedwait"][3])
    need(rc == "ETIMEDOUT" and 30_000_000_000 <= ns < 30_100_000_000, "timedwait")
elif g == "rs-threads":
    need(lines["mutex"] == ["8000"], "mutex")
    need(lines["condvar"] == ["200", "alternating", "true"], "condvar")
    want = sum(p * 1000 + i for p in range(4) for i in range(250))
    need(lines["mpsc"] == ["1000", str(want)], "mpsc")
    need(1_500_000_000 <= int(lines["sleep"][0]) < 1_501_000_000, "sleep")
    need(700_000_000 <= int(lines["park_timeout"][0]) < 701_000_000, "park_timeout")
    need(int(lines["unpark"][1]) < 60_000_000_000, "unpark")
    need(lines["pool"][0] == str(sum(j * j for j in range(2000))), "pool")
elif g == "order":
    log = out.strip()
    c = collections.Counter(log)
    need(len(log) == 32 and sorted(c) == list("abcdefgh") and set(c.values()) == {4}, "order log")
else:
    need(False, "unknown guest")
