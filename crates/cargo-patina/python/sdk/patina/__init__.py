"""Patina's SDK for Python guests.

Fault sites a deterministic simulation run fires from its seed, invariant and
coverage sites it reports on, verdicts, lifecycle markers, seeded entropy and
run parameters. It lowers to the same native-shim entry points as the Rust SDK
(patina-dst) and the Go SDK (go/patina), so a site or verdict means the same
thing in every language.

Every Python guest `patina build --python` builds has this package. Under
plain Python (this directory on the path) it is inert: no site fires, every
check returns its condition and nothing else happens, so code ships the SDK
unconditionally.

Sites are declared once, at module level, so a run knows every site the
module declares whether or not it is ever reached::

    import patina

    sorted_ = patina.Always("ledger-sorted")
    retried = patina.Sometimes("request-retried")
    drained = patina.Reachable("queue-drained")
    drop_flush = patina.Buggify("flush-early-drop")

    def settle(ledger):
        if drop_flush.fires():
            return
        sorted_.check(ledger == sorted(ledger), f"ledger={ledger}")

A declared site is what the Rust SDK calls a family: one label, any number of
callers. The part that varies per caller (a shard, a connection) goes in an
Always check's detail, not in its label.

A label names one site for the whole program: declaring it twice at
different places (or as different kinds) stops the run as a duplicate. Under
Patina an Always that sees false is a violation verdict and ends the run,
whose recorded trace replays to it; a Sometimes that never sees true, or a
Reachable never marked, is reported by the run and failed by a campaign.
"""

import enum
import math
import random
import sys
import threading

try:
    import _patina
except ImportError:  # plain Python: the inert stand-ins below
    _patina = None

__all__ = [
    "Always",
    "Buggify",
    "BuggifyDelay",
    "Knob",
    "Reachable",
    "Sometimes",
    "Verdict",
    "is_simulated",
    "lifecycle_event",
    "param",
    "rng",
    "setup_complete",
    "verdict",
]

# Site kinds, as the shim's static-site table numbers them.
_FAULT, _DELAY, _KNOB, _ALWAYS, _SOMETIMES, _REACHABLE = range(1, 7)


def _utf8(text):
    """`text` as the shim takes it: valid UTF-8, a lone surrogate replaced."""
    return text.encode("utf-8", "replace").decode("utf-8")


def _declaration_site():
    """The first frame outside this package: the declaration's file:line."""
    frame = sys._getframe(1)
    while frame is not None and frame.f_globals.get("__name__") == __name__:
        frame = frame.f_back
    if frame is None:
        return "unknown:0"
    return _utf8(f"{frame.f_code.co_filename}:{frame.f_lineno}")


class _Site:
    __slots__ = ("label", "where")
    _kind = 0

    def __init__(self, label):
        # The shim takes labels as UTF-8 and refuses anything else, so a bad
        # label fails here, at declaration, under plain Python too.
        if not isinstance(label, str) or not label or _utf8(label) != label:
            raise ValueError(f"patina: site label {label!r} must be a non-empty UTF-8 str")
        self.label = label
        self.where = _declaration_site()
        if _patina is not None:
            _patina.declare_site(self._kind, label, self.where)

    def __repr__(self):
        return f"{type(self).__name__}({self.label!r}) at {self.where}"


class Always(_Site):
    """An invariant: its condition must hold every time it is checked."""

    __slots__ = ()
    _kind = _ALWAYS

    def check(self, condition, detail=None):
        """Report `condition` and return it. Under Patina a false condition
        is a violation that ends the run; `detail` (formatted with str, and
        only on a violation) names the failing instance in the run's
        violation verdict."""
        condition = bool(condition)
        if _patina is not None:
            try:
                if not condition and detail is not None:
                    # The detail is a verdict of its own, reported before
                    # the check ends the run; a detail that fails to format
                    # must not cost the violation itself.
                    _patina.verdict(Verdict.VIOLATION, self.label, _utf8(str(detail)))
            finally:
                _patina.always(condition, self.label, self.where)
        return condition


class Sometimes(_Site):
    """A coverage oracle: a run (or campaign) that never sees its condition
    true is reported as not having exercised it."""

    __slots__ = ()
    _kind = _SOMETIMES

    def check(self, condition):
        """Note the site reached, and satisfied when `condition` is true.
        Returns `condition` and never changes control flow."""
        condition = bool(condition)
        if _patina is not None:
            _patina.sometimes(condition, self.label, self.where)
        return condition


class Reachable(_Site):
    """A coverage oracle for a point the run should reach."""

    __slots__ = ()
    _kind = _REACHABLE

    def mark(self):
        """Note the site reached."""
        if _patina is not None:
            _patina.reachable(self.label, self.where)


class Buggify(_Site):
    """A fault site: a rare path a run takes on seed-chosen evaluations, so
    the code behind it is exercised."""

    __slots__ = ()
    _kind = _FAULT

    def fires(self, probability=None):
        """Whether the site fires on this evaluation, at `probability` (0 to
        1) or the run's default. Under Patina an active site (`patina
        run --buggify`) fires as a pure function of the seed; outside Patina,
        and in a run without --buggify, it never does."""
        if _patina is None:
            return False
        # Half-up to per-mille, as the Go SDK rounds.
        permille = -1 if probability is None else math.floor(min(max(probability, 0.0), 1.0) * 1000 + 0.5)
        return _patina.buggify(self.label, self.where, permille) != 0


class BuggifyDelay(_Site):
    """A delay site: a deterministic delay through the virtual clock."""

    __slots__ = ()
    _kind = _DELAY

    def delay(self):
        """Advance virtual time when the site fires (never a real sleep) and
        report whether it did; outside Patina it does nothing."""
        if _patina is None:
            return False
        return _patina.buggify_delay(self.label, self.where) != 0


class Knob(_Site):
    """A tunable a run perturbs within bounds, so each seed explores a
    different configuration: `default` outside Patina and, under Patina, a
    per-run value in [low, high] for an active site."""

    __slots__ = ("default", "low", "high")
    _kind = _KNOB

    def __init__(self, label, default, low, high):
        self.default, self.low, self.high = int(default), int(low), int(high)
        super().__init__(label)

    def value(self):
        """The knob's value for this run."""
        if _patina is None:
            return self.default
        return _patina.buggify_knob(self.label, self.where, self.default, self.low, self.high)


class Verdict(enum.IntEnum):
    """What a guest concludes about its own run, numbered as the shim's
    verdict ABI numbers them."""

    #: The guest detected a violation of its own invariant.
    VIOLATION = 1
    #: The guest confirmed a property held.
    PASS = 2
    #: The guest is about to abort on its own invariant, so the abort is
    #: attributed to the guest, not to a Patina refusal.
    ABORT_INTENT = 3


def verdict(kind, label, detail=""):
    """Report a structured outcome about this run under `label`, which
    aggregates verdicts across runs, with `detail` (JSON by convention)
    recorded verbatim. Under Patina it is in the trace and the run's result
    verdicts; it never changes control flow. Outside Patina it does nothing.
    A verdict is not a site: one label may be reported any number of times."""
    if _patina is not None:
        _patina.verdict(Verdict(kind), label, detail)


def setup_complete():
    """Mark the boundary between setup and the workload. With `patina
    run --buggify-after-setup`, fault sites stay inert until it is called (and
    a run that never calls it fails). It does nothing outside Patina."""
    if _patina is not None:
        _patina.setup_complete()


def lifecycle_event(label):
    """Mark a named point in the run; it does nothing outside Patina."""
    if _patina is not None:
        _patina.lifecycle_event(label)


def is_simulated():
    """Whether the program runs under Patina."""
    return _patina is not None and _patina.is_simulated()


_fallback_lock = threading.Lock()
_fallback_rng = random.Random(0)


def rng():
    """A 64-bit draw from the run's seeded stream: under Patina a pure
    function of the seed, recorded and replayed with the run. Outside Patina
    a fixed-seed stream, so callers still get reproducible values without
    touching OS entropy."""
    if _patina is not None:
        return _patina.rng()
    with _fallback_lock:
        return _fallback_rng.getrandbits(64)


def param(key):
    """The run parameter `key` (`patina run --param KEY=VALUE`) as str,
    recorded in the trace and restored on replay; None when the run has none
    (and always outside Patina)."""
    if _patina is None:
        return None
    value = _patina.param(key)
    return None if value is None else value.decode("utf-8", "surrogateescape")

