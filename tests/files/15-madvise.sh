# 15. madvise, native against patina (tests/guests/fs/madvise.c): every advice value from 0 to 26
#     on private and shared, anonymous and file mappings: the return, the error, the bytes read
#     back and what a fork child reads are the same natively (the sandbox, no runtime) and under
#     patina, except MADV_FREE (8, and as 27 with the register's upper half set, which the kernel
#     ignores) and MADV_COLLAPSE (25), answered EINVAL with the pages as they were and recorded as
#     refused (natively FREE succeeds on private anonymous memory, its pages read back as they
#     were or as zeros at the kernel's choice; COLLAPSE depends on the host's huge pages). A
#     file mapping's pages are never put back from the file by FREE.
#@ tier=area budget=20
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/15-madvise
mkdir -p "$o"
native "$o/native" -- /guest/madvise || die "native madvise exit $?"
timeout 120 "$PATINA" run --seed 1 --out "$o/patina" --mount "$PATINA_GUESTS":/guest:copy -- /guest/madvise >/dev/null
[ "$(field "$o/patina/result.json" outcome)" = ok ] || die "patina madvise: $(field "$o/patina/result.json" outcome)"
refused=$(field "$o/patina/result.json" refused)
case $refused in *'"madvise:free"'*'"madvise:collapse"'* | *'"madvise:collapse"'*'"madvise:free"'*) ;; *) die "MADV_FREE and MADV_COLLAPSE not recorded as refused: $refused" ;; esac
[ "$(field "$o/patina/result.json" exit)" = 0 ] || die "patina madvise: exit $(field "$o/patina/result.json" exit)"
python3 -I - "$o/native/stdout" "$o/patina/boot-1/stdout" <<'EOF'
import sys
native, patina = (open(p).read().splitlines() for p in sys.argv[1:3])
assert len(native) == len(patina) > 0, (len(native), len(patina))
bad, kinds = [], set()
for n, p in zip(native, patina):
    nf, pf = n.split(), p.split()
    kinds.add(nf[0])
    if nf[:2] != pf[:2]:
        sys.exit(f"FAIL: lines out of step: {n!r} / {p!r}")
    if nf[1] in ("8", "25", "27"):
        # Refused: EINVAL, the pages as they were (page 0 written as 9, page 1 the file's 7 or
        # anonymous 0), and the child reads page 0 as written.
        want = ["ret", "-1", "EINVAL", "p0", "9", "p1", "7" if nf[0].startswith("file") else "0", "child", "9"]
        if pf[2:] != want:
            bad.append(f"patina {p!r}, want {' '.join(pf[:2] + want)!r}")
    elif nf != pf:
        bad.append(f"native {n!r}, patina {p!r}")
if bad:
    sys.exit("FAIL: " + "; ".join(bad[:8]))
assert kinds == {"anon-private", "anon-shared", "file-private", "file-shared"}, kinds
# Natively FREE is EINVAL on a file or shared mapping, as patina answers everywhere.
for n in native:
    f = n.split()
    if f[1] in ("8", "27") and f[0] != "anon-private" and f[3:5] != ["-1", "EINVAL"]:
        sys.exit(f"FAIL: native MADV_FREE on {f[0]}: {n!r}")
print(f"madvise: {len(native)} calls the same natively and under patina, FREE and COLLAPSE refused")
EOF
