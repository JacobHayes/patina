"""Patina's SDK for Python: invariants, coverage sites, fault points, knobs and marks, reported
to a Patina run through one reserved system call (ctypes over libc's ``syscall``; no build step).

Outside Patina the kernel answers the call ENOSYS; the first call learns that, and from then on
every method returns at once. Copy this file next to your program, or ``pip install`` the
directory that holds it.

Sites are declared once, at module level, so a run knows every site before it is reached::

    import patina
    SORTED = patina.Always("ledger-sorted")
    RETRIED = patina.Sometimes("request-retried")
    DROP_FLUSH = patina.Buggify("flush-early-drop")

    def settle(ledger):
        if DROP_FLUSH.fires():
            return
        SORTED.check(ledger == sorted(ledger), f"len {len(ledger)}")

Under Patina an ``Always`` that sees false ends the run with outcome ``violation`` and the
message ``label: detail``. A passing check reports only the first time it is evaluated in a
process (a ``Sometimes`` also the first time it holds). A fault point fires only with
``patina run --buggify``, on evaluations chosen by the seed and its label alone.

Compute points (Python 3.12 or later): ``python3 -m patina SCRIPT ARGS...`` (or ``-m MODULE``)
runs the program with a scheduling point and virtual time at every line and every pass of a
loop, so threads switch between any two lines and CPU-bound code moves the clock. Outside
Patina it runs the program as ``python3 SCRIPT`` would.

The wire is documented in sdk/c/patina.h of the Patina repository.
"""

import _thread
import ctypes
import os
import struct
import sys

__all__ = [
    "Always", "Unreachable", "Sometimes", "Reachable", "Buggify", "BuggifyDelay", "Knob",
    "mark", "setup_complete", "is_simulated", "compute", "control",
]

_SYSCALL = 0x7061
_VERSION = 1
_HELLO_BUGGIFY = 1 << 16
_HELLO, _ASSERT, _BUGGIFY, _KNOB, _DELAY, _MARK, _DECLARE = range(1, 8)
_CONTROL = 10
_ALWAYS, _SOMETIMES, _REACHABLE, _POINT, _KNOBK, _DELAYK, _UNREACHABLE = range(1, 8)
_NEVER = 2
_LABEL_MAX = 255
_TEXT_MAX = 4096
_HDR = struct.Struct("<BBHIqqq")
_EVAL, _HELD, _QUIET = 1, 2, 4
_ALL = _EVAL | _HELD | _QUIET

_state = None  # None: not asked; else (under Patina, buggify on)
_libc = None


def _sys(op, buf):
    global _libc
    if _libc is None:
        if not (sys.platform.startswith("linux") and os.uname().machine in ("x86_64", "aarch64")):
            return -38
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
        _libc.syscall.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_size_t]
    n = 0 if buf is None or isinstance(buf, int) else len(buf)
    r = _libc.syscall(_SYSCALL, op, buf, n)
    return -ctypes.get_errno() if r == -1 else r


def _get():
    global _state
    if _state is None:
        r = _sys(_HELLO, None)
        ok = r >= 0 and r & 0xFFFF == _VERSION
        if r >= 0 and not ok:
            sys.stderr.write("patina: unknown SDK protocol version; the SDK is inert\n")
        _state = (ok, ok and bool(r & _HELLO_BUGGIFY))
    return _state


def is_simulated():
    """Whether the process runs under Patina."""
    return _get()[0]


def _call(op, kind, cond, label, text=b"", a=0, b=0, c=0):
    label = label[:_LABEL_MAX]
    if len(text) > _TEXT_MAX:  # cut on a character boundary: back off continuation bytes
        n = _TEXT_MAX
        while n > 0 and text[n] & 0xC0 == 0x80:
            n -= 1
        text = text[:n]
    buf = ctypes.create_string_buffer(
        _HDR.pack(kind, 1 if cond else 0, len(label), len(text), a, b, c) + label + text,
        _HDR.size + len(label) + len(text),
    )
    r = _sys(op, buf)
    return r, struct.unpack_from("<q", buf.raw, 8)[0]


def _where():
    f = sys._getframe(1)
    while f is not None and f.f_code.co_filename == __file__:
        f = f.f_back
    if f is None:
        return b""
    return f"{f.f_code.co_filename}:{f.f_lineno}".encode("utf-8", "replace")


class _Site:
    _kind = 0

    def __init__(self, label):
        if not isinstance(label, str) or not label:
            raise ValueError(f"patina: site label {label!r} must be a non-empty str")
        self.label = label.encode("utf-8")
        if len(self.label) > _LABEL_MAX:
            raise ValueError(f"patina: site label {label!r} is longer than {_LABEL_MAX} bytes")
        if _get()[0]:
            self._bits = 0
            _call(_DECLARE, self._kind, False, self.label, _where())
        else:
            self._bits = _ALL

    def __repr__(self):
        return f"{type(self).__name__}({self.label.decode()!r})"

    def _report(self, cond, detail=None):
        if not _get()[0]:
            self._bits = _ALL
            return
        self._bits |= _EVAL | (_HELD if cond else 0)
        text = b""
        if not cond and detail is not None:
            text = str(detail).encode("utf-8", "replace")
        _call(_ASSERT, self._kind, cond, self.label, text)

    def _point(self, op, a):
        if self._bits & _QUIET:
            return False
        if not _get()[1]:
            self._bits = _ALL
            return False
        r, _ = _call(op, self._kind, False, self.label, b"", a)
        if r == _NEVER:
            self._bits |= _QUIET
        return r == 1


class Always(_Site):
    """An invariant: its condition must hold every time it is checked."""

    _kind = _ALWAYS

    def check(self, condition, detail=None):
        """Report and return the condition. Under Patina a false one ends the run as a
        violation; ``detail`` (formatted only then) names the failing instance."""
        condition = bool(condition)
        if not condition or not self._bits & _EVAL:
            self._report(condition, detail)
        return condition


class Unreachable(_Site):
    """A point that must not be reached. A run that never reaches it is not reported as
    unmet."""

    _kind = _UNREACHABLE

    def reached(self, detail=None):
        """The point was reached: under Patina the run ends as a violation."""
        self._report(False, detail)


class Sometimes(_Site):
    """A coverage site: its condition should hold on some runs."""

    _kind = _SOMETIMES

    def check(self, condition):
        condition = bool(condition)
        if not self._bits & (_HELD if condition else _EVAL):
            self._report(condition)
        return condition


class Reachable(_Site):
    """A coverage site: some run should reach it."""

    _kind = _REACHABLE

    def mark(self):
        if not self._bits & _EVAL:
            self._report(True)


class Buggify(_Site):
    """A fault point: a path the program can take, taken on seed-chosen evaluations."""

    _kind = _POINT

    def fires(self):
        """Whether the point fires now: never outside Patina or without --buggify."""
        return self._point(_BUGGIFY, -1)


class BuggifyDelay(_Site):
    """A delay point: sleeps a seeded virtual time (never real time) when it fires."""

    _kind = _DELAYK

    def delay(self, max_ns=0):
        """Sleep between 1 ms and 5 s (or up to ``max_ns``) of virtual time when the point
        fires; return whether it did."""
        return self._point(_DELAY, int(max_ns))


class Knob(_Site):
    """A tunable: ``default``, or under ``--buggify`` a seed-chosen value in [low, high]."""

    _kind = _KNOBK

    def __init__(self, label, default, low, high):
        super().__init__(label)
        self.default, self.low, self.high = int(default), int(low), int(high)

    def value(self):
        if not _get()[1]:
            return self.default
        r, v = _call(_KNOB, _KNOBK, False, self.label, b"", self.default, self.low, self.high)
        return v if r == 0 else self.default


def mark(label):
    """Name a point in the run's log."""
    if _get()[0]:
        _call(_MARK, _REACHABLE, False, label.encode("utf-8"))


def control(words):
    """A control call (the grammar is in ``patina.h``), e.g. ``control("net cut a b")``: raises
    ``OSError`` with the errno Patina answered (``EPERM`` outside the driver's node, ``ENOENT``
    for an unknown node, ``EINVAL`` for other words, ``EALREADY`` or ``EAGAIN`` for a node in the
    wrong state), or ``ENOSYS`` outside Patina."""
    if not _get()[0]:
        raise OSError(38, "control: not inside a Patina run")
    w = words.encode("utf-8")
    if not 0 < len(w) <= _TEXT_MAX:
        raise OSError(22, "control: expected 1 to %d bytes of words" % _TEXT_MAX)
    r = _sys(_CONTROL, ctypes.create_string_buffer(w, len(w)))
    if r < 0:
        raise OSError(-r, "control %r: %s" % (words, os.strerror(-r)))


def setup_complete():
    """The end of setup: with faults-after-setup, no fault fires before it."""
    mark("setup-complete")


# Compute points (ARCHITECTURE.md, "Compute points"): `python3 -m patina SCRIPT ARGS...` runs
# SCRIPT with them on. Each line the interpreter starts and each jump it takes (every pass of a
# loop, a one-line loop included) is LINE_EVENTS events: ``sys.monitoring`` calls the hook,
# which takes them from the cell the runtime maps and, when the cell runs out, makes the call
# COMPUTE_POINT, where the seed may switch threads. ctypes releases the GIL around that call,
# so the thread switched to can run Python code.
_COMPUTE_HELLO, _COMPUTE_POINT = 8, 9
_COMPUTE_VERSION = 1
_COMPUTE_LINE = 8
# Events (virtual ns) per line or jump: about what a line of plain Python takes natively.
LINE_EVENTS = 15
_compute_on = None


def compute():
    """Turn compute points on for this process (all its threads, and a fork child) from the
    next line on, and return whether they are on. Outside Patina: one failed call, then
    nothing, and False. Needs Python 3.12 or later (``sys.monitoring``)."""
    global _compute_on
    if _compute_on is not None:
        return _compute_on
    _compute_on = False
    mon = getattr(sys, "monitoring", None)
    if mon is None:
        if is_simulated():
            raise RuntimeError("patina: compute points need Python 3.12 or later (sys.monitoring)")
        return False
    addr = _sys(_COMPUTE_HELLO, _COMPUTE_VERSION | _COMPUTE_LINE << 8)
    if addr <= 0:
        return False
    cell = memoryview((ctypes.c_ubyte * 8).from_address(addr)).cast("B").cast("q")
    _compute_on = True
    tool = next((i for i in (4, 3) if mon.get_tool(i) is None), None)
    if tool is None:
        raise RuntimeError("patina: compute points need a free sys.monitoring tool id (3 or 4)")
    call = _libc.syscall
    E = mon.events
    # A signal arriving at a point runs its Python handler inside the hook. An exception it
    # raises in a line's hook reaches the program at that line, as natively. Raised in a
    # jump's hook, CPython 3.12 (all), 3.13.0–3.13.14 and 3.14.0–3.14.6 let it skip the
    # frame's handlers (python/cpython#152375, fixed in 3.13.15, 3.14.7 and 3.15), so the hook
    # keeps it and raises it from the next instruction of that code in that thread.
    held = {}

    def line(code, n, _c=cell, _n=LINE_EVENTS):
        v = _c[0] - _n
        _c[0] = v
        if v <= 0:
            call(_SYSCALL, _COMPUTE_POINT, None, 0)

    def jump(code, src, dst, _c=cell, _n=LINE_EVENTS):
        v = _c[0] - _n
        _c[0] = v
        if v <= 0:
            try:
                call(_SYSCALL, _COMPUTE_POINT, None, 0)
            except BaseException as e:
                held[_thread.get_ident()] = e
                mon.set_local_events(tool, code, E.INSTRUCTION)

    def instruction(code, offset):
        e = held.pop(_thread.get_ident(), None)
        if e is not None:
            mon.set_local_events(tool, code, 0)
            raise e

    mon.use_tool_id(tool, "patina")
    mon.register_callback(tool, E.LINE, line)
    mon.register_callback(tool, E.JUMP, jump)
    mon.register_callback(tool, E.INSTRUCTION, instruction)
    mon.set_events(tool, E.LINE | E.JUMP)
    return True


def _main(argv):
    import runpy

    if not argv or argv[0] in ("-h", "--help") or argv == ["-m"]:
        sys.stderr.write("usage: python3 -m patina SCRIPT [ARGS...] | -m MODULE [ARGS...]\n"
                         "Runs the program with Patina's compute points on (Python 3.12+).\n")
        sys.exit(2)
    try:
        compute()
    except RuntimeError as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)
    if argv[0] == "-m":
        sys.argv = argv[1:]
        runpy.run_module(argv[1], run_name="__main__", alter_sys=True)
    else:
        sys.argv = argv
        if not sys.flags.safe_path:
            sys.path[0] = os.path.dirname(os.path.realpath(argv[0]))
        runpy.run_path(argv[0], run_name="__main__")


if __name__ == "__main__":
    import patina

    patina._main(sys.argv[1:])
