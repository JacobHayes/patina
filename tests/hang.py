"""hang.py: what a check script that tests/run.py killed over its budget was doing, written to
RUNS/hang.txt (RUNS is the script's run directory, kept and uploaded with a failure).

    hang.py snapshot SID RUNS   before the kill: the script's processes as a tree (its session,
                                and every process of a run under RUNS by tests/leftovers.py's
                                rule: sandboxes leave the session), each thread's state, kernel
                                wait channel and CPU time, sampled twice a second apart: a thread
                                whose CPU time grew was computing, one whose did not was waiting;
                                prints `cpu SECONDS`: the CPU time of those processes and of the
                                children they reaped, at the end of the snapshot
    hang.py logs RUNS           after the kill: for each run under RUNS that has no result.json
                                (it was still going), its boundary log cut to the records written
                                (the launcher sizes the file ahead and cuts it only at the end),
                                its last records (`patina inspect dump`) and its keeper's log tail;
                                then RUNS is bounded to LIMIT bytes by deleting its largest files

Both append to RUNS/hang.txt and never fail the caller: what cannot be read is said there.
"""
import os
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REC = 96  # proto::rec::REC_SIZE; a record starts with seq and vclock_ns (u64 each)
LIMIT = 64 << 20
TAIL = 40


def read(p, default=""):
    try:
        with open(p, errors="replace") as f:
            return f.read()
    except OSError:
        return default


def stat(pid, tid=None):
    """(state, ppid, session) of a process or thread."""
    s = read(f"/proc/{pid}/task/{tid}/stat" if tid else f"/proc/{pid}/stat")
    f = s.rsplit(")", 1)[1].split() if ")" in s else []
    return (f[0], int(f[1]), int(f[3])) if len(f) > 3 else ("?", 0, 0)


def wchan(pid, tid):
    """Where the kernel holds a waiting thread ("-" when it is running)."""
    w = read(f"/proc/{pid}/task/{tid}/wchan").strip()
    return "-" if w in ("", "0") else w


def cpu_ns(pid, tid):
    s = read(f"/proc/{pid}/task/{tid}/schedstat").split()
    return int(s[0]) if s else None


def snapshot(sid, runs, out):
    pids = set()
    for name in os.listdir("/proc"):
        if name.isdigit() and stat(name)[2] == sid:
            pids.add(int(name))
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "leftovers.py"), runs],
                       stdout=subprocess.PIPE, text=True, timeout=60)
    for line in r.stdout.splitlines():
        try:
            pids.add(int(line.split()[0]))
        except (IndexError, ValueError):
            pass
    # Everything as it is at the kill; then each thread's CPU time again a second later.
    procs = {p: (stat(p), " ".join(read(f"/proc/{p}/cmdline").replace("\0", " ").split())[:400]) for p in pids}
    threads = {}
    for pid in pids:
        try:
            tids = sorted(int(t) for t in os.listdir(f"/proc/{pid}/task"))
        except OSError:
            continue
        for tid in tids:
            threads[(pid, tid)] = (read(f"/proc/{pid}/task/{tid}/comm").strip(), stat(pid, tid)[0],
                                   wchan(pid, tid), cpu_ns(pid, tid))
    time.sleep(1)
    kids = {}
    for p in sorted(pids):
        parent = procs[p][0][1]
        kids.setdefault(parent if parent in pids else None, []).append(p)
    out.write(f"== processes of the script (session {sid}) and of its runs, at the kill; "
              "cpu: a thread's CPU time, +N ms: its CPU time in the next second (exited: it ended)\n")

    def show(p, depth):
        (state, _, _), argv = procs[p]
        out.write(f"{'  ' * depth}{p} [{state}] {argv or '(exited)'}\n")
        for (pp, tid), (comm, tstate, wch, before) in sorted(threads.items()):
            if pp != p or before is None:
                continue
            now = cpu_ns(p, tid)
            grew = f"+{(now - before) / 1e6:.0f} ms" if now is not None else "exited"
            out.write(f"{'  ' * depth}  thread {tid} {comm} [{tstate}] wchan {wch} cpu {before / 1e6:.0f} ms ({grew})\n")
        for k in kids.get(p, []):
            show(k, depth + 1)

    for p in kids.get(None, []):
        show(p, 0)
    # The tree's CPU time just before the kill, for run.py's FAIL line: the killed processes are
    # never reaped by the script, so its rusage leaves them out. Each live process counts its own
    # time and that of the children it reaped (stat fields utime, stime, cutime, cstime).
    ticks = 0
    for p in pids:
        s = read(f"/proc/{p}/stat")
        f = s.rsplit(")", 1)[1].split() if ")" in s else []
        if len(f) > 14:
            ticks += sum(int(x) for x in f[11:15])
    print(f"cpu {ticks / os.sysconf('SC_CLK_TCK'):.2f}", flush=True)


def logs(runs, out):
    patina = os.environ.get("PATINA")
    for d, dirs, files in sorted(os.walk(runs)):
        dirs.sort()
        if "boundary.log" not in files or os.path.exists(os.path.join(os.path.dirname(d), "result.json")):
            continue
        log = os.path.join(d, "boundary.log")
        out.write(f"\n== unfinished run: {log}\n")
        try:
            with open(log, "r+b") as f:
                b = f.read()
                n = len(b) // REC
                while n and not any(b[(n - 1) * REC:n * REC]):
                    n -= 1
                f.truncate(n * REC)
        except OSError as e:
            out.write(f"   cannot read it: {e}\n")
            continue
        if not n:
            out.write("   no records\n")
            continue
        seq, vclock = struct.unpack_from("<QQ", b, (n - 1) * REC)
        out.write(f"   {n} records (the file is cut to them); the last: seq {seq}, virtual time {vclock} ns; "
                  f"its last {TAIL}:\n")
        if patina:
            r = subprocess.run([patina, "inspect", "dump", log, "--from", str(max(0, seq - TAIL))],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
            for line in r.stdout.splitlines()[-TAIL:]:
                out.write(f"   {line}\n")
        keeper = read(os.path.join(d, "sandbox.log")).splitlines()
        if keeper:
            out.write("   sandbox.log, its end:\n" + "".join(f"   {l}\n" for l in keeper[-10:]))
    sizes = []
    for d, _, files in os.walk(runs):
        for n in files:
            p = os.path.join(d, n)
            if os.path.isfile(p) and not os.path.islink(p) and n != "hang.txt":
                sizes.append((os.path.getsize(p), p))
    total = sum(s for s, _ in sizes)
    for s, p in sorted(sizes, reverse=True):
        if total <= LIMIT:
            break
        os.remove(p)
        total -= s
        out.write(f"deleted {p} ({s} bytes): the run directory is kept under {LIMIT >> 20} MiB\n")


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    runs = args[-1]
    with open(os.path.join(runs, "hang.txt"), "a") as out:
        try:
            snapshot(int(args[0]), runs, out) if cmd == "snapshot" else logs(runs, out)
        except Exception as e:  # what was gathered stays; the reason is said
            out.write(f"hang.py {cmd}: {type(e).__name__}: {e}\n")


if __name__ == "__main__":
    main()
