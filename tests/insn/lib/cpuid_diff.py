"""Compare cpuid dumps (lines "leaf sub eax ebx ecx edx") taken on different cores.

usage: python3 -I cpuid_diff.py DUMP...
Prints one line per (leaf, register) whose value differs between dumps:
  diff leaf=0000000b reg=edx bits=000000ff subleaves=0-63
with the OR of the differing bits over all subleaves and pairs, then a summary line
"leaves=N lines=N differing=N". Exit 0 always (the caller decides what the result means)."""
import sys

REGS = ("eax", "ebx", "ecx", "edx")


def load(p):
    d = {}
    for line in open(p):
        f = line.split()
        if len(f) != 6:
            continue
        d[(int(f[0], 16), int(f[1], 16))] = [int(x, 16) for x in f[2:]]
    return d


dumps = [load(p) for p in sys.argv[1:]]
keys = sorted(set().union(*dumps))
bits = {}
subs = {}
for k in keys:
    vals = [d.get(k) for d in dumps]
    if any(v is None for v in vals):
        print(f"missing leaf={k[0]:08x} sub={k[1]:02x}")
        continue
    for r in range(4):
        x = 0
        for v in vals[1:]:
            x |= v[r] ^ vals[0][r]
        if x:
            key = (k[0], REGS[r])
            bits[key] = bits.get(key, 0) | x
            subs.setdefault(key, []).append(k[1])
for (leaf, reg), b in sorted(bits.items()):
    s = subs[(leaf, reg)]
    rng = f"{min(s)}-{max(s)}" if len(s) > 1 else str(s[0])
    print(f"diff leaf={leaf:08x} reg={reg} bits={b:08x} subleaves={rng} ({len(s)})")
print(f"leaves={len(set(k[0] for k in keys))} lines={len(keys)} differing={len(bits)}")
