"""objdump_sites.py SITES < OBJDUMP: every patched instruction of a plan (`patina __rewrite
--sites` lines: site ADDR LEN, each instruction of a group its own) against `objdump -d -w` of the same file on stdin, a decode made
without the rewriter. Prints `objdump-check sites=N disagree=M` and the first disagreements: a
site that objdump does not show as one instruction of the same length."""
import re
import sys

want = {}
with open(sys.argv[1]) as f:
    for text in f:
        kind, addr, length = text.split()
        if kind != "site":
            continue
        want[int(addr, 16)] = int(length)
seen = {}
line = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t")
for text in sys.stdin:
    m = line.match(text)
    if m:
        a = int(m.group(1), 16)
        if a in want:
            seen[a] = len(m.group(2).split())
bad = [a for a, n in want.items() if seen.get(a) != n]
for a in sorted(bad)[:10]:
    print(f"disagree {a:#x}: plan length {want[a]}, objdump {seen.get(a)}")
print(f"objdump-check sites={len(want)} disagree={len(bad)}")
