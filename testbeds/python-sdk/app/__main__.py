"""A Python guest instrumented with Patina's Python SDK (the `patina` package):
an invariant, a coverage site satisfied on some seeds' draws, a point always
reached, and a point never reached, all declared at module level; a fault
site, a delay site and a knob; a setup boundary; a pass verdict; seeded
entropy; under the run parameter `ops`, custom operations, one with a declared
failure; and the run parameter `violate` (or, outside Patina, an argument)
that breaks the invariant."""

import json
import sys
import threading
import time

import patina

ordered = patina.Always("python-sdk-ledger-sorted")
even_draw = patina.Sometimes("python-sdk-even-draw")
settled = patina.Reachable("python-sdk-settled")
never = patina.Reachable("python-sdk-never-reached")
drop_draw = patina.Buggify("python-sdk-drop-draw")
stall = patina.BuggifyDelay("python-sdk-stall")
width = patina.Knob("python-sdk-ledger-width", 8, 4, 16)

# The custom operations whose real effect ran.
performed = 0


def perform(value):
    """The real effect: a count, and computation enough to cross the compute
    meter's points, which take no scheduling point inside a custom op. It
    stays in C (sum over a range) and allocates nothing that lives, so it
    leaves the interpreter as the replay, which never runs it, finds it."""
    global performed
    performed += 1
    sum(range(200_000))
    return value


violate = patina.param("violate") is not None or "violate" in sys.argv[1:]
patina.setup_complete()
patina.lifecycle_event("python-sdk-workload")

ledger = []
dropped = 0
for _ in range(width.value()):
    draw = patina.rng() % 1000
    if drop_draw.fires(0.5):
        draw = 0
        dropped += 1
    even_draw.check(draw % 2 == 0)
    ledger.append(draw)
    stall.delay()
ledger.sort()
if violate:
    ledger[0], ledger[-1] = ledger[-1], ledger[0]
held = ordered.check(ledger == sorted(ledger), f"ledger={ledger}")
settled.mark()
if not ledger:
    never.mark()

# With the run parameter `ops`: an effect Patina does not model, with a
# declared failure, and one without. A run records their results and a replay
# returns them without performing either. Another thread waits meanwhile,
# which a perform must not hand the interpreter to.
fetched, plain = "-", "-"
if patina.param("ops") is not None:
    sleeper = threading.Thread(target=time.sleep, args=(1,))
    sleeper.start()
    fetched = patina.custom_op(
        "python-sdk.fetch",
        {"object": "ledger"},
        lambda: perform("etag-7"),
        on_fault=lambda: "UNAVAILABLE",
    )
    plain = patina.custom_op_bytes("python-sdk.plain", b"seven", lambda: perform(b"7")).decode()
    sleeper.join()
if held:
    patina.verdict(patina.Verdict.PASS, "python-sdk-ledger-settled", json.dumps({"width": len(ledger)}))
print(
    f"PY_SDK_RESULT simulated={patina.is_simulated()} held={held} first={ledger[0]} "
    f"width={len(ledger)} dropped={dropped} performed={performed} fetched={fetched} plain={plain}"
)
