"""The rewriter's evidence workload for CPython: json, re, zlib, hashlib, sorting and four threads
whose results are joined; prints the same lines on every run."""
import hashlib
import json
import re
import threading
import zlib

doc = {"k%d" % i: [i, str(i) * 3, {"x": i % 7}] for i in range(20000)}
text = json.dumps(doc, sort_keys=True)
back = json.loads(text)
words = re.findall(r'"k(\d+)7"', text)
packed = zlib.compress(text.encode(), 6)
digest = hashlib.sha256(packed).hexdigest()
results = [0] * 4


def work(n):
    s = 0
    for i in range(200000):
        s = (s * 31 + i * n) % 1000003
    results[n] = s


threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(len(back), len(words), len(packed), digest[:16])
print(sorted(int(w) for w in words)[:5], results)
