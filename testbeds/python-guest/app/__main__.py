"""python-guest: a Python application built with `cargo patina build --python`.

It prints one `PYTHON_GUEST` line per fact it checks, so the testbed compares
runs line by line. With the argument `boom` it raises after them, with
`interrupt` it raises KeyboardInterrupt, and with `fork` it calls os.fork,
which the virtual machine refuses.
"""

import asyncio
import dataclasses
import datetime
import decimal
import hashlib
import json
import os
import pathlib
import random
import re
import sys
import threading
import time

import ledger
import tally
from plugins.greeting import hello


def fact(name, value):
    print(f"PYTHON_GUEST {name}={value}")


fact("argv", ",".join(sys.argv[1:]) or "-")
fact("version", sys.version.split()[0])

# The application's own module shadows the site-packages one of the same name,
# and a site-packages package and a namespace package import.
fact("shadow", ledger.ORIGIN)
fact("tally", tally.total([3, 4, 5]))
fact("namespace", hello("patina"))

# The standard library, pure and C.
fact("json", json.dumps({"b": [1, 2], "a": None}, sort_keys=True))
fact("decimal", decimal.Decimal("1.10") + decimal.Decimal("2.205"))
fact("sha256", hashlib.sha256(b"patina").hexdigest()[:16])
fact("blake2b", hashlib.blake2b(b"patina", digest_size=8).hexdigest())
fact("re", re.sub(r"(\w+)@(\w+)", r"\2 at \1", "dst@patina"))


@dataclasses.dataclass(frozen=True)
class Point:
    x: int
    y: int


fact("dataclass", Point(1, 2))

# Seeded randomness, and the virtual clocks.
fact("random", random.Random().randrange(1_000_000))
fact("urandom", os.urandom(4).hex())
start = time.monotonic()
time.sleep(0.25)
fact("slept", round(time.monotonic() - start, 3))
fact("utc", datetime.datetime.fromtimestamp(86400 * 365, datetime.timezone.utc).isoformat())
fact("local", time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(86400 * 180)))
fact("mktime", int(time.mktime((1971, 6, 30, 12, 0, 0, 0, 0, -1))))


async def gather():
    async def after(delay, value):
        await asyncio.sleep(delay)
        return value

    return await asyncio.gather(after(0.2, "late"), after(0.1, "early"))


fact("asyncio", asyncio.run(gather()))

# A thread that computes without calls stops when the main thread says so:
# the compute meter keeps the interpreter switching between them.
stop = threading.Event()
spins = [0]


def spin():
    while not stop.is_set():
        spins[0] += 1


worker = threading.Thread(target=spin)
worker.start()
time.sleep(0.05)
stop.set()
worker.join()
fact("metered", spins[0] > 0)

# The guest filesystem.
path = pathlib.Path("notes.txt")
path.write_text("one\ntwo\n")
fact("file", path.read_text().splitlines())

if "boom" in sys.argv[1:]:
    ledger.settle({"open": 1})
if "interrupt" in sys.argv[1:]:
    raise KeyboardInterrupt
if "fork" in sys.argv[1:]:
    os.fork()
