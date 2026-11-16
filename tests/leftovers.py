"""leftovers.py DIR [--ns NS]... [--started-before SECONDS]: print one line per process of this user that still
belongs to a run under DIR, and exit 1 if there is any.

A process belongs to a run if it has a descriptor, a mapping or its working directory under
DIR. Every process of a run qualifies while it lives: the launcher (its run directory's files),
bwrap and the supervisor (the run's boundary log at a fixed descriptor), and every guest process
(the runtime holds the boundary log at a hidden descriptor and maps it), so this finds what a
run left behind without looking at other runs on the host. Command lines are not used: a shell
merely mentioning DIR (someone watching the run) is not part of it. With --ns (a namespace
as /proc/PID/ns/* names it, e.g. "pid:[4026533390]", captured while the run lives), a process in
that namespace also counts, unless it started after --started-before (seconds since boot, as
/proc/uptime reads; give the time the namespaces were captured): namespace numbers are reused
once a namespace ends, so a later sandbox of a concurrent check can get the same one.
This process and its ancestors (the calling scripts, which may have DIR as their working
directory or hold an output file under it) are skipped."""
import os
import sys

root = os.path.realpath(sys.argv[1]).rstrip("/") + "/"
nss = set()
before = None
args = sys.argv[2:]
while args:
    if args[0] == "--ns" and len(args) > 1:
        nss.add(args[1])
        args = args[2:]
    elif args[0] == "--started-before" and len(args) > 1:
        before = float(args[1])
        args = args[2:]
    else:
        sys.exit("usage: leftovers.py DIR [--ns NS]... [--started-before SECONDS]")
TICK = os.sysconf("SC_CLK_TCK")


def started(pid):
    """Start time of a process, seconds since boot."""
    with open(f"/proc/{pid}/stat") as f:
        return int(f.read().rsplit(")", 1)[1].split()[19]) / TICK

skip = set()
p = os.getpid()
while p > 1:
    skip.add(p)
    try:
        with open(f"/proc/{p}/status") as f:
            p = int(next(l for l in f if l.startswith("PPid:")).split()[1])
    except (OSError, StopIteration):
        break

uid = os.getuid()


def under(path):
    return (path.rstrip("/") + "/").startswith(root) or path.startswith(root)


def why(pid):
    d = f"/proc/{pid}"
    if os.stat(d).st_uid != uid:
        return None
    for ns in os.listdir(f"{d}/ns") if nss and (before is None or started(pid) <= before) else []:
        try:
            if os.readlink(f"{d}/ns/{ns}") in nss:
                return f"in the run's namespace {ns}"
        except OSError:
            pass
    try:
        for fd in os.listdir(f"{d}/fd"):
            try:
                if under(os.readlink(f"{d}/fd/{fd}")):
                    return f"descriptor {fd}"
            except OSError:
                pass
    except OSError:
        pass
    try:
        with open(f"{d}/maps") as f:
            for line in f:
                parts = line.split(None, 5)
                if len(parts) == 6 and under(parts[5].strip()):
                    return "mapping"
    except OSError:
        pass
    try:
        if under(os.readlink(f"{d}/cwd")):
            return "working directory"
    except OSError:
        pass
    return None


found = 0
for name in os.listdir("/proc"):
    if not name.isdigit() or int(name) in skip:
        continue
    try:
        w = why(int(name))
        if w:
            with open(f"/proc/{name}/comm") as f:
                comm = f.read().strip()
            print(f"{name} {comm}: {w}")
            found += 1
    except OSError:
        pass  # exited while being looked at
sys.exit(1 if found else 0)
