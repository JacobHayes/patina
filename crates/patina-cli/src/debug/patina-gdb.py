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
    # arm64 watchpoints trap before the access, and gdb steps over it with the SIGTRAP it
    # passes on: the step lands in the runtime's handler and the access traps again, forever.
    if not S["watchpoints"]:
        for c in ("watch", "rwatch", "awatch"):
            gdb.execute("define hook-%s\npython no_watch()\nend" % c)
else:
    gdb.execute("handle SIGTRAP stop print nopass")

def no_step():
    raise gdb.GdbError("patina: no stepping in this run (its scheduling points share SIGTRAP "
                       "with the debugger); use breakpoints%s and continue"
                       % (" or watchpoints" if S["watchpoints"] else ""))

def no_watch():
    raise gdb.GdbError("patina: no watchpoints in this run on arm64 (its scheduling points "
                       "share SIGTRAP with the debugger, which steps over each hit); use "
                       "breakpoints and continue, or record the seed again under "
                       "[sched] preempt = \"traps\" (another schedule)")

def trap_passes(on):
    if PASS:
        gdb.execute("with confirm off -- handle SIGTRAP nostop noprint %s"
                    % ("pass" if on else "nopass"), to_string=True)

def vet(bp):
    """In a run whose SIGTRAPs are passed on, gdb must report every stop at a breakpoint (the
    stop turns passing off, `on_stop`): one it takes and goes on from by itself (a condition,
    an ignore count, another thread's, a dprintf) would step over it with the SIGTRAP passed,
    into the runtime's handler and back, forever; a software watchpoint steps the program.
    So does an arm64 watchpoint (it traps before the access). Such a breakpoint is disabled.
    (A Python breakpoint whose `stop` answers False is the same, and not seen here.)"""
    if not PASS or not bp.is_valid() or not bp.enabled:
        return
    why = None
    if bp.type == gdb.BP_WATCHPOINT:
        why = "a software watchpoint steps the program"
    elif bp.type in (gdb.BP_HARDWARE_WATCHPOINT, gdb.BP_READ_WATCHPOINT,
                     gdb.BP_ACCESS_WATCHPOINT) and not S["watchpoints"]:
        why = "an arm64 watchpoint stops before the access and gdb steps over it"
    elif bp.condition or bp.ignore_count or bp.thread is not None or getattr(bp, "task", None) is not None \
            or getattr(gdb, "BP_DPRINTF", None) == bp.type:
        why = "gdb would go on from it by itself (a condition, an ignore count, a thread, a dprintf)"
    else:
        for l in getattr(bp, "locations", ()):
            if l.address is not None and moved(int(l.address)):
                why = "its address is in code the plan moved, which runs in a trampoline"
                break
    if why:
        bp.enabled = False
        print("patina: breakpoint %d disabled: %s, and this run's scheduling points share "
              "SIGTRAP with the debugger; use a plain breakpoint and continue" % (bp.number, why))

def on_stop(e):
    """Name a SIGTRAP stop gdb did not cause: Ctrl-C (the runtime turns gdb's SIGINT into a
    SIGTRAP to itself), or the supervisor's spin probe (from PID 1), which gdb keeps. In a run
    whose SIGTRAPs are passed on, the stop's own SIGTRAP (a breakpoint's) is not: until the
    program goes on (`on_cont`), so that gdb's step over the breakpoint does not take the
    program into its handler and back to the breakpoint, forever."""
    trap_passes(False)
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

def moved(a):
    """Whether address `a` is in original code a plan moved to a trampoline (not run there)."""
    return any(orig <= a < orig + n for _, _, orig, n, _ in TRAMP)

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
    thread whose sandbox id is `tid` (its first thread when 0). The world stays held from the
    detach until the attach has stopped the new process: gdb reports events between the two
    (with no process attached), and none of them is the user letting the world go."""
    SWITCHING[0] = True
    try:
        if gdb.selected_inferior().pid not in (0, hpid):
            gdb.execute("detach", to_string=True)
        if gdb.selected_inferior().pid != hpid:
            gdb.execute("attach %d" % hpid, to_string=True)
    finally:
        SWITCHING[0] = False
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
        # gdb reports no stop at a call's end and puts back the thread's last stop signal: a
        # breakpoint's SIGTRAP, which must not be passed when the program goes on.
        trap_passes(False)

def on_cont(e):
    release()
    trap_passes(True)

gdb.events.cont.connect(on_cont)
gdb.events.gdb_exiting.connect(lambda e: go())
gdb.execute("define hook-detach\npython release()\nend")
gdb.events.before_prompt.connect(before_prompt)
gdb.events.stop.connect(on_stop)
gdb.events.breakpoint_created.connect(vet)
gdb.events.breakpoint_modified.connect(vet)
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
