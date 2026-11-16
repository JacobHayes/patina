"""Append entries to a journal file, then read it back: every entry must be there, whole.

The bug: os.write may write fewer bytes than asked, and `append` ignores the count it returns.
`journal.py fixed` writes the rest. A failed call (OSError) stops the program, which is fine.
"""
import os
import sys

import patina

INTACT = patina.Always("journal-intact")
SHORT = patina.Sometimes("short-write-seen")


def append(fd, data, fixed):
    n = os.write(fd, data)
    SHORT.check(n < len(data))
    while fixed and n < len(data):  # the fix
        n += os.write(fd, data[n:])


def main():
    fixed = sys.argv[1:] == ["fixed"]
    entries = [f"entry {i:03} {'x' * (i % 50)}\n".encode() for i in range(200)]
    try:
        fd = os.open("journal", os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o644)
        for e in entries:
            append(fd, e, fixed)
        os.fsync(fd)
        os.close(fd)
        with open("journal", "rb") as f:
            got = f.read()
    except OSError as e:
        print(f"stopped: {e}")
        return
    INTACT.check(got == b"".join(entries), f"{len(got)} bytes")
    print(f"{len(entries)} entries written and read back")


main()
