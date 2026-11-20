# patina debug's gdb helper, written next to the stop's facts (debug.json) for one session.
# It attaches to the process at the stop and gives gdb what it cannot find itself: the
# program's and its libraries' symbols at their load addresses (the kernel's exe and auxv are
# Patina's runtime, which loads the program), the thread at the stop, the runtime's own
# signals let through, and frames the runtime's code stands in for. It tells patina when the
# debugger lets the world go on (continue, detach, quit) and what the session did that leaves
# the recorded run (memory or register writes, calls into the program).
import gdb, json, os, struct, bisect
from gdb.unwinder import Unwinder

if int(gdb.VERSION.split(".")[0]) < 12:
    raise gdb.GdbError("patina debug needs gdb 12 or later (this is %s)" % gdb.VERSION)
S = json.load(open(STOP))
for c in ("set pagination off", "set confirm off", "set sysroot /",
          # The program's files are the program's: none of their scripts run here.
          "set auto-load gdb-scripts off", "set auto-load python-scripts off"):
    gdb.execute(c)
# Every system call is a SIGSYS to the runtime; some instructions fault on purpose.
gdb.execute("handle SIGSYS SIGSEGV SIGILL SIGBUS SIGFPE nostop noprint pass")
PASS = S["sigtrap_pass"]
if PASS:
    # The run's scheduling points take SIGTRAP: gdb passes on every one it did not cause and
    # the runtime drops what is not its own. gdb's own steps cannot be told apart: refused;
    # Ctrl-C's SIGTRAP is passed on and dropped too: no interrupt in this run.
    gdb.execute("handle SIGTRAP nostop noprint pass")
    for c in ("step", "next", "stepi", "nexti", "until", "advance"):
        gdb.execute("define hook-%s\npython no_step()\nend" % c)
else:
    gdb.execute("handle SIGTRAP stop print nopass")

def no_step():
    raise gdb.GdbError("patina: no stepping in this run (its scheduling points share SIGTRAP "
                       "with the debugger); use breakpoints or watchpoints and continue")

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

def ns_pid(status):
    for l in status.splitlines():
        if l.startswith("NSpid:"):
            return int(l.split()[-1])

TRAMP = []  # (start, end, original address, length, offset of the copy)

def tramp_orig(pc):
    i = bisect.bisect_right(TRAMP, (pc, 1 << 64)) - 1
    if i < 0 or not TRAMP[i][0] <= pc < TRAMP[i][1]:
        return None
    lo, _, orig, n, copy = TRAMP[i]
    off = pc - (lo + copy)
    return orig + off if 0 <= off < n else orig

class FrameId:
    def __init__(self, sp, pc):
        self.sp, self.pc = sp, pc

class Patina(Unwinder):
    """A trampoline frame's caller is the original code with the same registers; on arm64 the
    runtime's signal restorer is a signal frame (gdb knows only the kernel's instruction pair)."""

    def __init__(self):
        super().__init__("patina")
        try:
            self.restorer = int(gdb.parse_and_eval("(long)&patina_restorer"))
        except gdb.error:
            self.restorer = None

    def __call__(self, pf):
        pc, sp = int(pf.read_register("pc")), pf.read_register("sp")
        if pc == self.restorer:
            mc = int(sp) + 128 + 176  # rt_sigframe: siginfo, then the ucontext's mcontext
            w = struct.unpack("<34Q", bytes(gdb.selected_inferior().read_memory(mc + 8, 272)))
            new = dict(("x%d" % i, w[i]) for i in range(31))
            new.update(sp=w[31], pc=w[32])
        else:
            orig = tramp_orig(pc)
            if orig is None:
                return None
            new = {"pc": orig, "rip": orig}
        ui = pf.create_unwind_info(FrameId(sp, pc))
        for r in pf.architecture().registers():  # the rest as they are in this frame
            try:
                v = pf.read_register(r.name)
                ui.add_saved_register(r.name, gdb.Value(new[r.name]).cast(v.type) if r.name in new else v)
            except (gdb.error, ValueError):
                pass
        return ui

def quoted(path):
    return '"%s"' % path.replace("\\", "\\\\").replace('"', '\\"')

ATTACHED = [0]
UN = [None]
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
    m = next((p["maps"] for p in S["procs"] if p["host"] == hpid), {"images": [], "tramps": []})
    names = []
    for path, f, bias in m["images"]:
        try:
            gdb.execute("add-symbol-file %s -o %#x" % (quoted(f), bias), to_string=True)
            names.append(os.path.basename(path))
        except gdb.error as e:
            print("patina: no symbols for %s: %s" % (path, e))
    print("patina: symbols for %s" % ", ".join(names))
    TRAMP[:] = [tuple(t) for t in m["tramps"]]
    if TRAMP:
        print("patina: %d trampolines mapped to the code they stand for" % len(TRAMP))
    UN[0] = un = Patina()
    gdb.unwinder.register_unwinder(None, un, replace=True)
    for t in os.listdir("/proc/%d/task" % hpid):
        if tid and ns_pid(open("/proc/%d/task/%s/status" % (hpid, t)).read()) == tid:
            for th in gdb.selected_inferior().threads():
                if th.ptid[1] == int(t):
                    th.switch()
    # The program's frame: the one the runtime's signal frame interrupted.
    f = gdb.newest_frame()
    while f is not None and f.type() != gdb.SIGTRAMP_FRAME and f.pc() != un.restorer:
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
