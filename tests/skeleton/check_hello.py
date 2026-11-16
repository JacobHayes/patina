"""Structural check of a hello guest's stdout: python3 -I check_hello.py STDOUT GUEST ARG..."""
import re
import sys

path, guest, args = sys.argv[1], sys.argv[2], sys.argv[3:]
lines = open(path).read().splitlines()
want = [f"arg 0 /guest/{guest}"] + [f"arg {i + 1} {a}" for i, a in enumerate(args)] + ["pid 2"]
assert lines[: len(want)] == want, (lines[: len(want)], want)
rest = lines[len(want):]
clocks = [l for l in rest if l.startswith("clock ")]
assert len(clocks) == 100, len(clocks)
mono = [float(l.split()[2]) for l in clocks]
real = [float(l.split()[3]) for l in clocks]
assert all(b > a for a, b in zip(mono, mono[1:])), "monotonic clock must advance between reads"
assert all(b > a for a, b in zip(real, real[1:])), "realtime clock must advance between reads"
rnd = [l for l in rest if l.startswith("random ")]
assert len(rnd) == 1 and re.fullmatch(r"random [0-9a-f]{32}", rnd[0]), rnd
assert any(re.fullmatch(r"malloc 0x[0-9a-f]+", l) for l in rest)
assert any(re.fullmatch(r"stack 0x[0-9a-f]+", l) for l in rest)
st = [l for l in rest if l.startswith("stat ")]
assert len(st) == 1 and " size 6 " in st[0] and " mode 100644 " in st[0], st
names = [l.split()[1] for l in rest if l.startswith("dirent ")]
assert "hello.txt" in names, names
print("stdout ok:", path)
