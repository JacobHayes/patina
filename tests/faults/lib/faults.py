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
    """Where an ack-log boot crashed: the last record before the Crash record."""
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


SYNCS = ("Fsync", "FsyncDir", "FsyncFail", "Sync")


def points(ops):
    """The crash point ordinal just after each record (None for base records and the Crash
    record), as the runtime counts them in a run without `ready` probes: one point after each
    record it appends, and one before each sync-class call, ahead of the records that call
    appends (writeback, then the sync record; all with the call's seq). Scripts check what a
    run crashed at, so a difference from the runtime's count shows as a crash elsewhere."""
    sync_seqs = {o["seq"] for o in ops if o["kind"] in SYNCS}
    n, seen, out = 0, set(), []
    for o in ops:
        if o["pid"] == 0 or o["kind"] == "Crash":
            out.append(None)
            continue
        if o["seq"] in sync_seqs and o["seq"] not in seen:
            seen.add(o["seq"])
            n += 1
        n += 1
        out.append(n)
    return out


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "crash-position":
        for inc in sys.argv[2:]:
            print(crash_position(inc))
    elif cmd == "point-after":
        # point-after INC KIND NAME NTH: the crash point just after the NTH (1-based) KIND
        # record on NAME, and that record's seq
        inc, kind, name, nth = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
        ops = oplog(inc)
        nm = names(ops)
        pts = points(ops)
        hits = [i for i, o in enumerate(ops) if o["kind"] == kind and nm.get(o["ino"]) == name]
        print(pts[hits[nth - 1]], ops[hits[nth - 1]]["seq"])

