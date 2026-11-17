"""Instruction-site census of an ELF file.

usage: python3 -I census.py [--tsv] [--kinds k1,k2] FILE...
       python3 -I census.py --summary FILE-OR-DIRECTORY...    (arm64 files)

x86-64 files:

For every executable PT_LOAD segment, find the byte patterns of the instructions that can
observe run-to-run variation (and `syscall`, for the rewriting estimate), then classify each
hit with a linear-sweep disassembler (`objdump -d`): `real` when an instruction of the
expected mnemonic starts at the hit (or at prefixes right before it), otherwise `fp`
(the bytes are inside another instruction, or in bytes objdump does not disassemble).

The `scan` and `pause` kinds are exactly the runtime scanner's rule (`proto/src/insn/x86_64.rs`):
0F C7 with a register ModRM whose reg field is 6 or 7, i.e. rdrand, rdseed and (with an F3
prefix) rdpid; and F3 90, `pause`, which must start the instruction.

arm64 files (e_machine 183): every aligned word of each executable section (SHF_EXECINSTR)
that matches a kind: `rndr` (RNDR, RNDRRS), `pause` (yield, wfe, wfi, isb) and `pacga`, the
runtime's rule (`proto/src/insn/aarch64.rs`), and `counter` (mrs of the counter-timer
registers, trapped, not patched). Each match is classified as data (`fp`) when a literal load
(LDR/LDRSW/SIMD LDR by pc-relative offset) anywhere in the executable sections reads it or a
`$d` mapping symbol (the marker objdump uses; unstripped files only) covers it, else `real`.
--summary adds up every arm64 ELF file under the given paths: the words searched, the words
literal loads read, the words `$d` covers, the matches by class, and the matches in
non-executable sections (which the runtime never searches).
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


# arm64: kind -> [(mask, value)]
A64 = {
    "rndr": [(0xFFFFFFE0, 0xD53B2400), (0xFFFFFFE0, 0xD53B2420)],
    "pause": [(0xFFFFFFFF, 0xD503203F), (0xFFFFFFFF, 0xD503205F), (0xFFFFFFFF, 0xD503207F), (0xFFFFFFFF, 0xD5033FDF)],
    "pacga": [(0xFFE0FC00, 0x9AC03000)],
    # CNTVCT, CNTVCTSS, CNTFRQ, CNTPCT, CNTPCTSS
    "counter": [(0xFFFFFFE0, v) for v in (0xD53BE040, 0xD53BE0C0, 0xD53BE000, 0xD53BE020, 0xD53BE0A0)],
}


def a64_kind(w):
    if w >> 24 not in (0xD5, 0x9A):
        return None
    for k, pats in A64.items():
        if any(w & m == v for m, v in pats):
            return k
    return None


def a64_census(path, data):
    """(stats, [(va, kind, word, class)], {kind: matches in non-executable sections})"""
    from array import array
    import bisect
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    secs = []
    for i in range(shnum):
        _n, typ, flags, addr, off, size, link, _i, _a, _e = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
        secs.append((typ, flags, addr, off, size, link))
    marks = []  # (address, 'd' | 'x') from $d / $x mapping symbols
    for typ, _f, _a, off, size, link in secs:
        if typ != 2:
            continue
        stroff = secs[link][3]
        for k in range(size // 24):
            nm, _info, _o, _shn, val, _sz = struct.unpack_from("<IBBHQQ", data, off + k * 24)
            o = stroff + nm
            if nm and data[o] == 0x24 and data[o + 1] in b"dx" and data[o + 2] in (0, 0x2E):
                marks.append((val, chr(data[o + 1])))
    marks.sort()
    addrs = [a for a, _ in marks]
    stats = {"text_words": 0, "literal_words": 0, "dmap_words": 0}
    hits, nonexec = [], {}
    texts = []
    for typ, flags, addr, off, size, _l in secs:
        if not flags & 2 or typ == 8 or size < 4:  # SHF_ALLOC, not SHT_NOBITS
            continue
        skip = -addr % 4
        n = (size - skip) // 4
        words = array("I", data[off + skip:off + skip + 4 * n])
        base = addr + skip
        if flags & 4:
            texts.append((base, words))
            continue
        for w in words:
            k = a64_kind(w)
            if k:
                nonexec[k] = nonexec.get(k, 0) + 1
    literal = set()
    for base, words in texts:
        stats["text_words"] += len(words)
        for i, w in enumerate(words):
            if w & 0x3B000000 != 0x18000000:
                continue
            size = {(0, 0): 4, (0, 1): 4, (1, 0): 8, (1, 1): 8, (2, 0): 4, (2, 1): 16}.get((w >> 30, (w >> 26) & 1))
            if not size:
                continue
            t = base + 4 * i + ((((w >> 5) & 0x7FFFF) ^ 0x40000) - 0x40000) * 4
            literal.update(range(t, t + size, 4))
    for base, words in texts:
        end = base + 4 * len(words)
        stats["literal_words"] += sum(1 for a in literal if base <= a < end)
        for j, (a, c) in enumerate(marks):
            if c == "d" and base <= a < end:
                stop = marks[j + 1][0] if j + 1 < len(marks) else end
                stats["dmap_words"] += max(0, min(stop, end) - a) // 4
        for i, w in enumerate(words):
            k = a64_kind(w)
            if not k:
                continue
            va = base + 4 * i
            j = bisect.bisect_right(addrs, va) - 1
            if va in literal:
                cls = "literal"
            elif j >= 0 and marks[j][1] == "d":
                cls = "$d"
            else:
                cls = "insn"
            hits.append((va, k, w, cls))
    return stats, hits, nonexec


def a64_files(paths):
    import os
    for p in paths:
        walk = [p] if not os.path.isdir(p) else sorted(os.path.join(d, f) for d, _, fs in os.walk(p) for f in fs)
        for f in walk:
            if os.path.islink(f) or not os.path.isfile(f):
                continue
            try:
                with open(f, "rb") as fh:
                    if fh.read(20)[:4] != b"\x7fELF":
                        continue
                    fh.seek(0)
                    data = fh.read()
            except OSError:
                continue
            if data[4] == 2 and struct.unpack_from("<H", data, 0x12)[0] == 183:
                yield f, data


def a64_summary(paths):
    tot = {"files": 0, "text_words": 0, "literal_words": 0, "dmap_words": 0}
    by, nonexec = {}, {}
    for f, data in a64_files(paths):
        try:
            stats, hits, ne = a64_census(f, data)
        except (struct.error, IndexError):
            print(f"skip\t{f}\tbad section headers")
            continue
        tot["files"] += 1
        for k, v in stats.items():
            tot[k] += v
        for k, v in ne.items():
            nonexec[k] = nonexec.get(k, 0) + v
        for va, k, w, cls in hits:
            by[(k, cls)] = by.get((k, cls), 0) + 1
            if cls != "insn":
                print(f"data\t{f}\t{k}\t{va:#x}\t{w:08x}\t{cls}")
    print("summary\t" + " ".join(f"{k}={v}" for k, v in tot.items()))
    for k in A64:
        print(f"exec\t{k}\t" + " ".join(f"{c}={by.get((k, c), 0)}" for c in ("insn", "literal", "$d")))
    print("nonexec\t" + " ".join(f"{k}={nonexec.get(k, 0)}" for k in A64))


def a64_main(path, data, tsv, kinds):
    _stats, hits, _ne = a64_census(path, data)
    counts = {}
    for va, k, w, cls in hits:
        if kinds is not None and k not in kinds:
            continue
        c = "real" if cls == "insn" else "fp"
        counts.setdefault(k, {"real": 0, "fp": 0})[c] += 1
        if tsv:
            print(f"site\t{path}\t{k}\t{va:#x}\t{c}\tword {w:08x} ({cls})")
    for k in A64:
        if kinds is not None and k not in kinds:
            continue
        c = counts.get(k, {"real": 0, "fp": 0})
        print(f"count\t{path}\t{k}\treal={c['real']}\tfp={c['fp']}")


def main():
    args = sys.argv[1:]
    if args and args[0] == "--summary":
        return a64_summary(args[1:])
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
        a64 = dict(a64_files([path]))
        if path in a64:
            a64_main(path, a64[path], tsv, kinds)
            continue
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
