# patina debug's gdb helper, written next to the stop's facts (debug.json) for one session.
# It attaches to the process at the stop and gives gdb what it cannot find itself: the
# program's and its libraries' symbols at their load addresses (the kernel's exe and auxv are
# Patina's runtime, which loads the program), the thread at the stop, and the runtime's own
# signals let through. It tells patina when the debugger lets the world go on (continue,
# detach, quit) and what the session did that leaves the recorded run (memory or register
# writes, calls into the program).
import gdb, json, os, struct

if int(gdb.VERSION.split(".")[0]) < 12:
    raise gdb.GdbError("patina debug needs gdb 12 or later (this is %s)" % gdb.VERSION)
S = json.load(open(STOP))
for c in ("set pagination off", "set confirm off", "set sysroot /",
          # The program's files are the program's: none of their scripts run here.
          "set auto-load gdb-scripts off", "set auto-load python-scripts off"):
    gdb.execute(c)
# Every system call is a SIGSYS to the runtime; some instructions fault on purpose.
gdb.execute("handle SIGSYS SIGSEGV SIGILL SIGBUS SIGFPE nostop noprint pass")
gdb.execute("handle SIGTRAP stop print nopass")


def on_stop(e):
    """Name a SIGTRAP stop gdb did not cause: Ctrl-C (the runtime turns gdb's SIGINT into a
    SIGTRAP to itself), or the supervisor's spin probe (from PID 1), which gdb keeps."""
    try:
        i = gdb.parse_and_eval("$_siginfo")
        trap = int(i["si_signo"]) == 5 and int(i["si_code"]) == -6
    except gdb.error:
        trap = False
    if trap and not isinstance(e, gdb.BreakpointEvent):
        pid = int(i["_sifields"]["_kill"]["si_pid"])
        print("patina: " + ("a spin probe of the supervisor's, not passed on: the run goes on "
                            "as recorded unless the program was spinning" if pid == 1
                            else "interrupted (Ctrl-C)"))


def note(what):
    with open(S["notes"], "a") as f:
        f.write(what + "\n")


def elf_lo(path):
    """The lowest page of an ELF file's loadable segments, or None."""
    try:
        with open(path, "rb") as f:
            h = f.read(64)
            if h[:4] != b"\x7fELF" or h[4] != 2:
                return None
            phoff, = struct.unpack_from("<Q", h, 32)
            size, n = struct.unpack_from("<HH", h, 54)
            f.seek(phoff)
            lo = None
            for _ in range(n):
                ph = f.read(size)
                if struct.unpack_from("<I", ph, 0)[0] == 1:
                    v = struct.unpack_from("<Q", ph, 16)[0] & ~0xfff
                    lo = v if lo is None else min(lo, v)
            return lo
    except OSError:
        return None


def ns_pid(status):
    for l in status.splitlines():
        if l.startswith("NSpid:"):
            return int(l.split()[-1])


def images(hpid):
    """The file gdb should read for each image the process maps, and its load bias. A path
    the host does not have as the guest's (a copied program) is read through the process's
    own root."""
    out = {}
    for line in open("/proc/%d/maps" % hpid):
        w = line.split(None, 5)
        if len(w) < 6 or not w[5].startswith("/") or int(w[2], 16) != 0:
            continue
        path = w[5].rstrip("\n")
        if path in out or path.endswith(" (deleted)"):
            continue
        inside = "/proc/%d/root%s" % (hpid, path)
        try:
            same = os.path.samestat(os.stat(path), os.stat(inside))
        except OSError:
            same = False
        f = path if same else inside
        lo = elf_lo(f)
        if lo is not None:
            out[path] = (f, int(w[0].split("-")[0], 16) - lo)
    return out


def quoted(path):
    return '"%s"' % path.replace("\\", "\\\\").replace('"', '\\"')


ATTACHED = [0]
SWITCHING = [False]


def attach(hpid, tid):
    """Attach to host process `hpid` (detaching from another), with symbols, and select the
    thread whose sandbox id is `tid` (its first thread when 0)."""
    inf = gdb.selected_inferior()
    if inf.pid not in (0, hpid):
        SWITCHING[0] = True
        try:
            gdb.execute("detach", to_string=True)
        finally:
            SWITCHING[0] = False
    if gdb.selected_inferior().pid != hpid:
        gdb.execute("attach %d" % hpid, to_string=True)
    ATTACHED[0] = hpid
    exe = os.readlink("/proc/%d/exe" % hpid)
    names = []
    for path, (f, bias) in images(hpid).items():
        if path == exe:
            continue
        try:
            gdb.execute("add-symbol-file %s -o %#x" % (quoted(f), bias), to_string=True)
            names.append(os.path.basename(path))
        except gdb.error as e:
            print("patina: no symbols for %s: %s" % (path, e))
    print("patina: symbols for %s" % ", ".join(names))
    for t in os.listdir("/proc/%d/task" % hpid):
        if tid and ns_pid(open("/proc/%d/task/%s/status" % (hpid, t)).read()) == tid:
            for th in gdb.selected_inferior().threads():
                if th.ptid[1] == int(t):
                    th.switch()
    # The program's frame: the one the runtime's signal frame interrupted.
    f = gdb.newest_frame()
    while f is not None and f.type() != gdb.SIGTRAMP_FRAME:
        f = f.older()
    if f is not None and f.older() is not None:
        f.older().select()
    gdb.execute("frame", to_string=False)


CALLING = [0]  # a call gdb makes into the program runs with the world still held


def go():
    if not os.path.exists(S["release"]):
        open(S["release"], "w").close()


def release(*_):
    if not SWITCHING[0] and not CALLING[0]:
        go()


def before_prompt():
    if ATTACHED[0] and gdb.selected_inferior().pid == 0:
        release()


def on_call(e):
    if isinstance(e, gdb.InferiorCallPreEvent):
        CALLING[0] += 1
        note("call")
    else:
        CALLING[0] -= 1


gdb.events.cont.connect(release)
gdb.events.gdb_exiting.connect(lambda e: go())
gdb.execute("define hook-detach\npython release()\nend")
gdb.events.before_prompt.connect(before_prompt)
gdb.events.stop.connect(on_stop)
gdb.events.memory_changed.connect(lambda e: note("memory"))
gdb.events.register_changed.connect(lambda e: note("register"))
gdb.events.inferior_call.connect(on_call)
gdb.events.exited.connect(lambda e: print(
    "patina: the process exited; the run goes on (quit to see how it ends)")
    if hasattr(e, "exit_code") else None)


def procs():
    """The sandbox's guest processes now: (sandbox pid, host pid, name)."""
    out = []
    for d in os.listdir("/proc"):
        try:
            if not d.isdigit() or os.readlink("/proc/%s/ns/pid" % d) != S["pidns"]:
                continue
            pid = ns_pid(open("/proc/%s/status" % d).read())
            name = open("/proc/%s/comm" % d).read().strip()
        except OSError:
            continue
        if pid != 1:
            out.append((pid, int(d), "".join(c if c.isprintable() else "?" for c in name)))
    return sorted(out)


class PatinaCmd(gdb.Command):
    """patina where | patina procs | patina attach PID: the stop, the sandbox's processes,
    another process (by its sandbox pid; the world stays parked until you continue)."""

    def __init__(self):
        super().__init__("patina", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        w = arg.split()
        if w == ["where"]:
            print("stopped before seq %d: %s; process %d (host pid %d), thread %d" % (
                S["seq"], S["event"], S["pid"], S["host_pid"], S["tid"]))
        elif w == ["procs"]:
            node = dict((p["pid"], p["node"]) for p in S["procs"])
            for pid, host, name in procs():
                print("%s pid %d  host pid %d  %s%s" % (
                    "*" if host == gdb.selected_inferior().pid else " ", pid, host, name,
                    "  node " + node[pid] if node.get(pid) else ""))
        elif len(w) == 2 and w[0] == "attach" and w[1].isdigit():
            hosts = [h for p, h, _ in procs() if p == int(w[1])]
            if not hosts:
                raise gdb.GdbError("patina: no process %s in the sandbox (patina procs)" % w[1])
            attach(hosts[0], S["tid"] if hosts[0] == S["host_pid"] else 0)
        else:
            raise gdb.GdbError("usage: patina where | patina procs | patina attach PID")


PatinaCmd()
print("patina: stopped before seq %d: %s" % (S["seq"], S["event"]))
attach(S["host_pid"], S["tid"])
