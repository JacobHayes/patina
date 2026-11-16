# Mask the values the differential test may not compare (fs-tour output): timestamps, device
# numbers, inode numbers of pipes and other anonymous objects, mount ids, statfs f_fsid,
# addresses, and lines tagged "virt" (answers that are virtual by design: limits, system
# information, refused interfaces, MADV_FREE, hidden descriptors).
import re, sys

S_IFMT, S_IFIFO, S_IFSOCK = 0o170000, 0o010000, 0o140000

def zero(h, off, n):
    return h[:2 * off] + "--" * n + h[2 * (off + n):]

def le(h, off, n):
    return int.from_bytes(bytes.fromhex(h[2 * off:2 * (off + n)]), "little")

def mask_line(l, anon_labels):
    m = re.match(r"^(virt|addr) (\S+) ", l)
    if m:
        return f"{m.group(1)} {m.group(2)} *"
    m = re.match(r"^(stat|statx|statfs) (\S+) ([0-9a-f]{64,})$", l)
    if m:
        kind, label, h = m.groups()
        if kind == "stat":
            h = zero(h, 0, 8)                      # st_dev
            h = zero(h, 72, 48)                    # atime, mtime, ctime
            mode = le(h, 24, 4)
            if mode & S_IFMT in (S_IFIFO, S_IFSOCK) and "pipe" in label or label in anon_labels:
                h = zero(h, 8, 8)                  # st_ino of an anonymous object
        elif kind == "statx":
            h = zero(h, 64, 64)                    # atime, btime, ctime, mtime
            h = zero(h, 136, 16)                   # dev major/minor, mount id
        elif kind == "statfs":
            h = zero(h, 40, 16)                    # f_files, f_ffree (tmpfs: sized from host RAM)
            h = zero(h, 56, 8)                     # f_fsid
        return f"{kind} {label} {h}"
    l = re.sub(r"pipe:\[\d+\]", "pipe:[*]", l)
    l = re.sub(r"socket:\[\d+\]", "socket:[*]", l)
    if l.startswith("readlink-pipe = "):
        l = "readlink-pipe = *"
    return l

anon = set(sys.argv[2:])
for line in open(sys.argv[1], errors="replace"):
    # Supplementary groups are virtual under patina (the namespace's primary group alone);
    # natively they are the launcher's, unmapped ones as the overflow id.
    if line.startswith("group ") or line.startswith("getgroups = "):
        continue
    print(mask_line(line.rstrip("\n"), anon))
