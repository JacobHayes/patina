"""Instruction-site census of an ELF file.

usage: python3 -I census.py [--tsv] [--kinds k1,k2] FILE...

For every executable PT_LOAD segment, find the byte patterns of the instructions that can
observe run-to-run variation (and `syscall`, for the rewriting estimate), then classify each
hit with a linear-sweep disassembler (`objdump -d`): `real` when an instruction of the
expected mnemonic starts at the hit (or at prefixes right before it), otherwise `fp`
(the bytes are inside another instruction, or in bytes objdump does not disassemble).

The `scan` and `pause` kinds are exactly the runtime scanner's rule (`rt/src/insn/scan.rs`):
0F C7 with a register ModRM whose reg field is 6 or 7, i.e. rdrand, rdseed and (with an F3
prefix) rdpid; and F3 90, `pause`, which must start the instruction.
"""
import struct
import subprocess
import sys

# kind -> (pattern bytes, predicate on the byte after the pattern or None, mnemonics)
PATTERNS = {
    "scan": (b"\x0f\xc7", lambda m: m >> 6 == 3 and (m >> 3) & 7 in (6, 7), ("rdrand", "rdseed", "rdpid")),
    "pause": (b"\xf3\x90", None, ("pause",)),
    "rdtsc": (b"\x0f\x31", None, ("rdtsc",)),
    "rdtscp": (b"\x0f\x01\xf9", None, ("rdtscp",)),
    "cpuid": (b"\x0f\xa2", None, ("cpuid",)),
    "rdpru": (b"\x0f\x01\xfd", None, ("rdpru",)),
    "rdpmc": (b"\x0f\x33", None, ("rdpmc",)),
    "xgetbv": (b"\x0f\x01\xd0", None, ("xgetbv",)),
    "lsl": (b"\x0f\x03", None, ("lsl",)),
    "xbegin": (b"\xc7\xf8", None, ("xbegin",)),
    "syscall": (b"\x0f\x05", None, ("syscall",)),
}
PREFIXES = set(range(0x40, 0x50)) | {0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65, 0xF0}


def exec_segments(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise SystemExit(f"{path}: not a 64-bit ELF")
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(phnum):
        typ, flags, off, vaddr, _pa, filesz, _memsz, _al = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if typ == 1 and flags & 1:
            segs.append((off, vaddr, filesz))
    return data, segs


def hits(data, segs):
    out = []  # (vaddr of the pattern, kind)
    for off, vaddr, filesz in segs:
        seg = data[off:off + filesz]
        for kind, (pat, pred, _m) in PATTERNS.items():
            i = seg.find(pat)
            while i >= 0:
                if pred is None or (i + len(pat) < len(seg) and pred(seg[i + len(pat)])):
                    out.append((vaddr + i, kind))
                i = seg.find(pat, i + 1)
    return sorted(out)


def classify(path, hs):
    """Map each hit to ('real'|'fp', instruction text) using one objdump linear sweep."""
    res = {}
    if not hs:
        return res
    p = subprocess.Popen(["objdump", "-d", "-w", "-z", path], stdout=subprocess.PIPE, text=True, errors="replace")
    j = 0
    for line in p.stdout:
        if j >= len(hs):
            continue
        if not line.startswith(" ") or ":\t" not in line:
            continue
        a, rest = line.split(":\t", 1)
        try:
            start = int(a.strip(), 16)
        except ValueError:
            continue
        parts = rest.split("\t")
        nbytes = len(parts[0].split())
        text = parts[1].strip() if len(parts) > 1 else ""
        end = start + nbytes
        while j < len(hs) and hs[j][0] < start:
            j += 1  # never covered by a disassembled instruction: padding or data
        while j < len(hs) and hs[j][0] < end:
            va, kind = hs[j]
            mn = text.split()[0] if text else ""
            mnems = PATTERNS[kind][2]
            ok = any(mn.startswith(m) for m in mnems)
            if ok and kind == "pause":
                ok = va == start
            elif ok and va != start:
                # prefixes only between the instruction start and the pattern
                ok = va - start <= 4
            res[(va, kind)] = ("real" if ok else "fp", f"{start:x}+{va - start}: {text}")
            j += 1
    p.wait()
    for h in hs:
        res.setdefault(h, ("fp", "not disassembled (padding or data)"))
    return res


def main():
    args = sys.argv[1:]
    tsv = False
    kinds = None
    while args and args[0].startswith("--"):
        if args[0] == "--tsv":
            tsv, args = True, args[1:]
        elif args[0] == "--kinds":
            kinds, args = set(args[1].split(",")), args[2:]
        else:
            raise SystemExit(f"unknown option {args[0]}")
    for path in args:
        try:
            data, segs = exec_segments(path)
        except (SystemExit, OSError, struct.error) as e:
            print(f"skip\t{path}\t{e}")
            continue
        hs = [h for h in hits(data, segs) if kinds is None or h[1] in kinds]
        cl = classify(path, hs)
        counts = {}
        for (va, kind), (c, text) in sorted(cl.items()):
            counts.setdefault(kind, {"real": 0, "fp": 0})[c] += 1
            if tsv and kind != "syscall":
                print(f"site\t{path}\t{kind}\t{va:#x}\t{c}\t{text}")
        for kind in PATTERNS:
            if kinds is not None and kind not in kinds:
                continue
            c = counts.get(kind, {"real": 0, "fp": 0})
            print(f"count\t{path}\t{kind}\treal={c['real']}\tfp={c['fp']}")


main()
