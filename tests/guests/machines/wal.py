#!/usr/bin/env python3
"""A machine that appends records to a log and recovers it after its machine crashes.

    wal.py NAME [nocheck]   recover `wal`, then append records to it, fsyncing every fourth,
                            and serve :7000
    wal.py main SECONDS   ask machine a what it recovered, every 0.2 s for SECONDS

A record is `R1`, its payload's length (2 bytes), the payload's CRC-32 (4 bytes), then the
payload, `r<I>-<N>-` padded with `x` to a length that depends on N (I is PATINA_BOOT less 1,
N the record's number in that boot). An append the machine crash catches before it
reached the disk can survive as zeros, or cut short.

Recovery reads records from the start. The correct machine stops at the first that is not whole
and valid (magic, length, CRC), truncates the log there and fsyncs it. The planted bug
`nocheck` trusts each header's length and keeps whatever it reads, stopping only at the end of
the file.

On each connection the machine sends one line, `inc=I recovered=R dropped=D bad=B first=P`: R
records recovered, D bytes cut off the end, B recovered records whose payload is not one any
machine wrote (checked against the payload its own number names), P the first of those (`-` when
none). Main prints `ok ...` and how many boots dropped a torn tail, or `FAIL: torn record
recovered: ...` and exits 1.
"""
import os
import socket
import struct
import sys
import time
import zlib

MAGIC = b"R1"
HDR = 8


def payload(inc, n):
    p = f"r{inc}-{n}-".encode()
    return p + b"x" * (5 + n % 23)


def valid(p):
    """A payload some machine wrote: the one its own `r<I>-<N>-` prefix names."""
    try:
        inc, n, _ = p.decode().split("-", 2)
        return p == payload(int(inc[1:]), int(n))
    except (UnicodeDecodeError, ValueError):
        return False


def recover(check):
    """The records of `wal`, and the bytes cut off its end."""
    try:
        with open("wal", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return [], 0
    recs, off = [], 0
    while off + HDR <= len(data):
        magic, n, crc = struct.unpack_from("<2sHI", data, off)
        p = data[off + HDR:off + HDR + n]
        if check and (magic != MAGIC or n == 0 or len(p) < n or zlib.crc32(p) != crc):
            break
        if len(p) < n:
            break
        recs.append(p)
        off += HDR + n
    if not check:
        return recs, 0
    cut = len(data) - off
    if cut:
        fd = os.open("wal", os.O_WRONLY)
        os.ftruncate(fd, off)
        os.fsync(fd)
        os.close(fd)
    return recs, cut


def machine(check):
    inc = int(os.environ.get("PATINA_BOOT", "1")) - 1
    recs, cut = recover(check)
    bad = [p for p in recs if not valid(p)]
    first = bad[0].hex() if bad else "-"
    line = f"inc={inc} recovered={len(recs)} dropped={cut} bad={len(bad)} first={first}\n"
    print(line, end="", flush=True)
    fd = os.open("wal", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    d = os.open(".", os.O_RDONLY)
    os.fsync(d)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000))
    s.listen(8)
    s.settimeout(0.02)
    n = 0
    while True:
        p = payload(inc, n)
        os.write(fd, struct.pack("<2sHI", MAGIC, len(p), zlib.crc32(p)) + p)
        n += 1
        if n % 4 == 0:
            os.fsync(fd)
        if n % 3 == 0:
            # Another file's fsync commits the journal: the log's new size with it, and not
            # always its data.
            with open("progress", "w") as f:
                f.write(str(n))
                f.flush()
                os.fsync(f.fileno())
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        c.sendall(line.encode())
        c.close()


def main(seconds):
    seen = {}
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        c = socket.socket()
        c.settimeout(1)
        try:
            c.connect(("a", 7000))
            line = c.makefile("r").readline().strip()
        except OSError:
            c.close()
            time.sleep(0.1)
            continue
        c.close()
        r = dict(w.split("=") for w in line.split())
        seen[r["inc"]] = r
        time.sleep(0.2)
    bad = [r for r in seen.values() if r["bad"] != "0"]
    for r in bad:
        print(f"FAIL: torn record recovered: boot {r['inc']}: {r['bad']} records no machine wrote, "
              f"first {r['first']}", flush=True)
    if bad:
        sys.exit(1)
    torn = sum(r["dropped"] != "0" for r in seen.values())
    print(f"ok {len(seen)} boots of a recovered only records it wrote")
    print(f"a torn tail dropped in {torn} of {len(seen)} boots")


if __name__ == "__main__":
    if sys.argv[1] == "main":
        main(float(sys.argv[2]))
    else:
        machine(sys.argv[2:] != ["nocheck"])
