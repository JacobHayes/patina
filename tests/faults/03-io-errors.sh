# 3. Error injection: fs-error-permille=100 gives non-zero tallies of legal errnos for
# every class, identical across 4 runs of a seed, and no failed call left an effect
# (a close that returned EIO still closed the descriptor); fs-error-at=write:7 fails
# exactly the 7th write and the file proves it was not made.
#@ tier=quick
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/03/tally
verify "$o" 5 4 "" --fault fs-error-permille=100 -- /guest/io-errors tally
[ "$(class "$o/run-0")" = ok ] || die "tally run: $(class "$o/run-0")"
python3 -I - "$o/run-0/inc-0/stdout" <<'PY' || exit 1
import sys
legal = {"open": {"EIO", "ENOSPC", "EMFILE", "ENOMEM"}, "read": {"EIO"}, "write": {"EIO", "ENOSPC"},
         "sync": {"EIO"}, "rename": {"EIO", "ENOSPC"}, "unlink": {"EIO", "ENOSPC"},
         "mkdir": {"EIO", "ENOSPC"}, "truncate": {"EIO", "ENOSPC"}, "link": {"EIO", "ENOSPC"},
         "fallocate": {"EIO", "ENOSPC"}, "close": {"EIO"}}
# natural results the guest can see without injection
natural = {"mkdir": {"EEXIST"}}
inj = {c: 0 for c in legal}
bad = []
viol = None
for line in open(sys.argv[1]):
    f = line.split()
    if f[0] == "tally":
        c, e, n = f[1], f[2], int(f[3])
        if e == "ok":
            continue
        if e in legal[c]:
            inj[c] += n
        elif e not in natural.get(c, ()):
            bad.append(line.strip())
    elif f[0] == "violations":
        viol = int(f[1])
for c, n in inj.items():
    print("%-10s %d injected errors" % (c, n))
if bad:
    sys.exit("FAIL: illegal errnos: %s" % bad)
if [c for c, n in inj.items() if n == 0]:
    sys.exit("FAIL: classes without errors: %s" % [c for c, n in inj.items() if n == 0])
if viol != 0:
    sys.exit("FAIL: %s failed calls left an effect" % viol)
print("violations 0 (failed calls left no effect; EIO from close still closed)")
PY
n=$(field "$o/run-0/outcome.json" faults.injected)
echo "faults injected per run: $n; 4 runs identical"
o=$RUNS/03/nth
run "$o" 1 --fault fs-error-at=write:7 -- /guest/io-errors nth
cat "$o/inc-0/stdout"
[ "$(grep -c ': ok$' "$o/inc-0/stdout")" = 9 ] || die "fs-error-at=write:7: not exactly one failed write"
grep -qx 'write 7: EIO' "$o/inc-0/stdout" || grep -qx 'write 7: ENOSPC' "$o/inc-0/stdout" || die "write 7 did not fail"
grep -q 'contents (27 bytes): W1 W2 W3 W4 W5 W6 W8 W9 W0' "$o/inc-0/stdout" || die "the failed write left an effect"
echo "fs-error-at=write:7: exactly the 7th write failed; its record is not in the file"
