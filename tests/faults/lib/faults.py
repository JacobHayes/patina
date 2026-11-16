"""Helpers for the faults scripts: operation logs and outcomes of run directories."""
import json, os, struct, sys

KINDS = ["", "Root", "Create", "Mkdir", "Symlink", "Link", "Unlink", "Rmdir", "Rename", "Write",
         "Truncate", "Fallocate", "SetAttr", "XattrSet", "XattrRemove", "MmapShared", "MmapDirty",
         "Fsync", "FsyncDir", "FsyncFail", "Sync", "Close", "Crash"]


def oplog(inc):
    meta = open(os.path.join(inc, "oplog.meta"), "rb").read()
    data = open(os.path.join(inc, "oplog.data"), "rb").read()
    out = []
    for i in range(0, len(meta), 96):
        seq, vt, kind, pid, ino = struct.unpack_from("<QQIIQ", meta, i)
        a = struct.unpack_from("<6Q", meta, i + 32)
        off, ln = struct.unpack_from("<QQ", meta, i + 80)
        out.append(dict(seq=seq, vt=vt, kind=KINDS[kind], pid=pid, ino=ino, a=a, data=data[off:off + ln]))
    return out


def names(ops):
    """inode -> last name it was created, linked or renamed under."""
    n = {}
    for o in ops:
        if o["kind"] in ("Create", "Mkdir", "Link"):
            n[o["ino"]] = o["data"].decode(errors="replace")
        elif o["kind"] == "Rename":
            n[o["ino"]] = o["data"][o["a"][4]:].decode(errors="replace")
    return n


def crash_position(inc):
    """Where an ack-log incarnation crashed: the last record before the Crash record."""
    ops = oplog(inc)
    if not ops or ops[-1]["kind"] != "Crash":
        return None
    nm = names(ops)
    prev = [o for o in ops[:-1] if o["kind"] != "Close"]
    if not prev:
        return "start"
    p = prev[-1]
    who = nm.get(p["ino"], "?")
    if p["kind"] == "Write":
        return "write->fsync (%s)" % who
    if p["kind"] == "Fsync" and who == "data.log":
        return "fsync->ack-write"
    if p["kind"] == "Rename":
        return "rename->dir-fsync"
    return "%s (%s)" % (p["kind"], who)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "crash-position":
        for inc in sys.argv[2:]:
            print(crash_position(inc))
    elif cmd == "seq-after":
        # seq-after INC KIND NAME NTH: seq of the NTH (1-based) KIND record on NAME, +1
        inc, kind, name, nth = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
        ops = oplog(inc)
        nm = names(ops)
        hits = [o for o in ops if o["kind"] == kind and nm.get(o["ino"]) == name]
        print(hits[nth - 1]["seq"] + 1)
