# A Python program that walks the standard library, imports modules and does
# file work on /work. Prints a digest of everything it saw.
import glob
import hashlib
import importlib
import os
import sys

h = hashlib.sha256()


def see(*xs):
    for x in xs:
        h.update(repr(x).encode())


roots = sorted(glob.glob("/usr/lib/python3*"))
n = 0
for root in roots:
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            try:
                st = os.lstat(p)
            except OSError as e:
                see(p, e.errno)
                continue
            see(p, st.st_mode, st.st_size, st.st_nlink)
            n += 1
print("walked", n)

mods = [
    "json", "re", "collections", "itertools", "functools", "datetime", "decimal", "fractions", "random",
    "statistics", "string", "textwrap", "struct", "array", "heapq", "bisect", "csv", "configparser",
    "argparse", "logging", "pickle", "copy", "zlib", "gzip", "bz2", "lzma", "tarfile", "zipfile",
    "sqlite3", "email.parser", "xml.etree.ElementTree", "html.parser", "urllib.parse", "uuid",
    "base64", "unittest", "difflib", "typing", "dataclasses", "enum",
]
for m in mods:
    importlib.import_module(m)
print("imported", len(mods))

import mmap
import pathlib
import random
import shutil
import tempfile
import time
import uuid

see(random.random(), uuid.uuid4().hex, time.time(), os.urandom(8).hex(), id(object()) % 64)

work = pathlib.Path("/work/py")
work.mkdir()
for i in range(50):
    (work / f"f{i:02}.txt").write_text("line %d\n" % i * (i + 1))
with open(work / "big.bin", "wb") as f:
    f.write(bytes(range(256)) * 4096)
    f.flush()
    os.fsync(f.fileno())
with open(work / "big.bin", "r+b") as f:
    m = mmap.mmap(f.fileno(), 0)
    m[0:4] = b"MMAP"
    see(m[:8], len(m))
    m.flush()
    m.close()
for p in sorted(work.iterdir()):
    st = os.stat(p)
    see(p.name, st.st_size, st.st_mode, st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_dev)
    print("stat", p.name, st.st_size, oct(st.st_mode), st.st_ino, st.st_mtime_ns, st.st_dev)

with tempfile.TemporaryDirectory() as td:
    see(td)
    print("tempdir", td)
    shutil.copytree(work, os.path.join(td, "copy"))
    shutil.make_archive(os.path.join(td, "arch"), "gztar", os.path.join(td, "copy"))
    st = os.stat(os.path.join(td, "arch.tar.gz"))
    print("archive", st.st_size)
    with tempfile.NamedTemporaryFile(dir=td, delete=False) as nt:
        nt.write(b"named")
        print("named", nt.name)
    shutil.move(nt.name, os.path.join(td, "moved"))
    print("listing", sorted(os.listdir(td)))
shutil.rmtree(work)
print("exists", work.exists())
print("pid", os.getpid(), "cwd", os.getcwd(), "argv", sys.argv)
print("digest", h.hexdigest())
