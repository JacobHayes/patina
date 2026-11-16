"""Join the disassembler's classification of scanner candidates (census.py --tsv, kind `scan`)
with the runtime rule's verdicts (patina __insn-scan), per (file, address).

usage: python3 -I audit.py CENSUS.tsv SCAN.tsv
Prints one line per candidate and per-file totals; the last line is
"agree=N disagree=N real=N fp=N accepted=N rejected=N". Exit 1 if any candidate disagrees
(a false positive accepted, or a real site rejected)."""
import sys

dis = {}
for line in open(sys.argv[1]):
    f = line.rstrip("\n").split("\t")
    if f[0] == "site" and f[2] == "scan":
        dis[(f[1], int(f[3], 16))] = (f[4], f[5])
rule = {}
for line in open(sys.argv[2]):
    f = line.rstrip("\n").split("\t")
    if f[0] == "cand":
        rule[(f[1], int(f[2], 16))] = (f[3], f[4])
agree = disagree = real = fp = acc = rej = 0
for k in sorted(set(dis) | set(rule)):
    d = dis.get(k, ("missing", ""))
    r = rule.get(k, ("missing", ""))
    ok = (d[0] == "real") == (r[0] == "real")
    agree += ok
    disagree += not ok
    real += d[0] == "real"
    fp += d[0] == "fp"
    acc += r[0] == "real"
    rej += r[0] in ("inside", "skipped")
    print(f"{'ok ' if ok else 'BAD'} {k[0]} {k[1]:#x} objdump={d[0]} ({d[1]}) rule={r[0]} {r[1]}")
print(f"agree={agree} disagree={disagree} real={real} fp={fp} accepted={acc} rejected={rej}")
sys.exit(1 if disagree else 0)
