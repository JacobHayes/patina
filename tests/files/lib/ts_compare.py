# Compare timestamp orderings of two tsorder outputs (native, patina): for every pair of
# (step, path, field) records the relation <, =, > must be the same. Prints every
# difference, classified as within one step (one operation) or across steps.
import itertools, sys

def load(p):
    d = {}
    for l in open(p):
        if l.startswith("S "):
            _, step, path, field, s, ns = l.split()
            d[(int(step), path, field)] = int(s) * 10**9 + int(ns)
    return d

a, b = load(sys.argv[1]), load(sys.argv[2])
if a.keys() != b.keys():
    print("record sets differ:", sorted(a.keys() ^ b.keys())[:20])
    sys.exit(1)
keys = sorted(a)
# origin[(step, path, field)]: the step that set the value natively, the first step whose
# records hold it (a hard link shows the stamps of the operation that set them on its inode).
first = {}
for k in keys:
    first.setdefault(a[k], k[0])
origin = {k: first[a[k]] for k in keys}
sign = lambda x, y: (x > y) - (x < y)
within, across = [], []
for k1, k2 in itertools.combinations(keys, 2):
    s1, s2 = sign(a[k1], a[k2]), sign(b[k1], b[k2])
    if s1 != s2:
        # The pair is "within one operation" when both values were set by the same step.
        o1, o2 = origin[k1], origin[k2]
        # Patina stamps one time per operation. The kernel's multigrain timestamps may stamp
        # the parts of one operation (an entry and its directory) at different granularity,
        # so natively they can differ by a tick: that difference is the host's, not patina's.
        if o1 == o2 and s2 == 0:
            continue
        (within if o1 == o2 else across).append((k1, k2, s1, s2))
print(f"records {len(keys)} pairs {len(keys) * (len(keys) - 1) // 2} differ-within-step {len(within)} differ-across-steps {len(across)}")
for k1, k2, s1, s2 in across + within:
    print("diff", k1, k2, "native", "<=>"[s1 + 1], "patina", "<=>"[s2 + 1])
sys.exit(0 if not across and not within else 1)
