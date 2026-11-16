# Mask what a native run of a coreutils command may not be compared on: file times (ls, stat),
# device numbers (stat), mktemp's random names (drawn from host entropy natively).
import re, sys

for l in open(sys.argv[1], errors="replace"):
    l = l.rstrip("\n")
    l = re.sub(r"\b(Access|Modify|Change|Birth): \d{4}-\d\d-\d\d [0-9:.]+ [+-]\d{4}", r"\1: *", l)
    l = re.sub(r"Device: \S+", "Device: *", l)
    l = re.sub(r"[A-Z][a-z]{2} [ \d]\d ( \d{4}|\d\d:\d\d) ", "DATE ", l)
    l = re.sub(r"/tmp/tmp\.[A-Za-z0-9]{10}", "/tmp/tmp.*", l)
    print(l)
