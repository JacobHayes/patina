#!/bin/bash
# What each workload and language runtime uses of the open-ended query surfaces: ioctl requests,
# fcntl commands, prctl options, socket option (level, name) pairs, Deny hits, refusals and the
# calls made (surface "call").
# One run per workload, seed 1, faults off. Writes OUT/surfaces.tsv (workload, surface, value,
# count) and OUT/outcomes.tsv (workload, class, refused). Needs PATINA, OUT.
#   surfaces.sh [NAMES...]      default: every entry below
set -euo pipefail; shopt -s inherit_errexit
: "${PATINA:?}" "${OUT:?}"
. "$(dirname "$0")/../lib/entries.inc"
mkdir -p "$OUT"
names=${*:-$ENTRIES}
: >"$OUT/surfaces.tsv"
: >"$OUT/outcomes.tsv"
for n in $names; do
    entry "$n"
    d=$OUT/run-$n
    rm -rf "${d:?}"
    # shellcheck disable=SC2086
    timeout 900 "$PATINA" run --seed 1 --out "$d" --mount "$GDIR":/guest:copy $OPTS -- $CMD >/dev/null 2>"$d.err" || true
    python3 -I - "$n" "$d" >>"$OUT/outcomes.tsv" <<'PY'
import json, sys
o = json.load(open(sys.argv[2] + "/result.json"))
print("%s\t%s\t%s" % (sys.argv[1], o["outcome"], ",".join(o.get("refused", []))))
PY
    for inc in "$d"/boot-*; do
        "$PATINA" log dump "$inc/boundary.log"
    done | python3 -I -c '
import collections, re, sys
n = sys.argv[1]
c = collections.Counter()
for l in sys.stdin:
    m = re.match(r"seq=\d+ trap slot=\d+ t=\d+ (\w+) \[(\w+)\] args=\[([^\]]*)\] ret=(-?\d+)", l)
    if not m:
        continue
    name, cls, a = m.group(1), m.group(2), [int(x, 16) for x in m.group(3).split(", ")]
    c[("call", name)] += 1
    if name == "ioctl":
        c[("ioctl", "0x%x" % (a[1] & 0xffffffff))] += 1
    elif name == "fcntl":
        c[("fcntl", str(a[1]))] += 1
    elif name == "prctl":
        c[("prctl", str(a[0]))] += 1
    elif name in ("getsockopt", "setsockopt"):
        c[(name, "%d:%d" % (a[1], a[2]))] += 1
    if cls == "Deny":
        c[("deny", name)] += 1
for (s, v), k in sorted(c.items()):
    print("%s\t%s\t%s\t%d" % (n, s, v, k))
' "$n" >>"$OUT/surfaces.tsv"
    rm -f "$d"/boot-*/boundary.log "$d"/boot-*/oplog.data
done
cat "$OUT/outcomes.tsv"
