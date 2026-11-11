"""A Python guest instrumented with Patina's Python SDK (the `patina` package):
an invariant, a coverage site satisfied on some seeds' draws, a point always
reached, and a point never reached, all declared at module level; a fault
site, a delay site and a knob; a setup boundary; a pass verdict; seeded
entropy; and the run parameter `violate` (or, outside Patina, an argument)
that breaks the invariant."""

import json
import sys

import patina

ordered = patina.Always("python-sdk-ledger-sorted")
even_draw = patina.Sometimes("python-sdk-even-draw")
settled = patina.Reachable("python-sdk-settled")
never = patina.Reachable("python-sdk-never-reached")
drop_draw = patina.Buggify("python-sdk-drop-draw")
stall = patina.BuggifyDelay("python-sdk-stall")
width = patina.Knob("python-sdk-ledger-width", 8, 4, 16)

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

if held:
    patina.verdict(patina.Verdict.PASS, "python-sdk-ledger-settled", json.dumps({"width": len(ledger)}))
print(
    f"PY_SDK_RESULT simulated={patina.is_simulated()} held={held} first={ledger[0]} "
    f"width={len(ledger)} dropped={dropped}"
)
