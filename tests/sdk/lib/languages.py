import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sdk import LANGS, die, log_ops, native, run  # noqa: E402

INERT = "a=00000000000000000000 knob=7 delay=0\n"
tables, lines = {}, {}
for lang, cmd in LANGS.items():
    for mode in ["script", "fail"]:
        st, out, err = native(cmd, mode)
        if st != 0 or err:
            die(f"{lang} {mode} natively: exit {st}, stderr {err!r}")
        if mode == "script" and out != INERT:
            die(f"{lang} script natively printed {out!r}")

    r = run(f"01/{lang}-fail", 1, cmd, "fail")
    if r.cls != "violation" or r.outcome["message"] != "must-hold: balance -1" or r.status != r.outcome["exit"] or r.status == 0:
        die(f"{lang} fail: {r.cls} exit {r.status} {r.outcome['message']!r}")
    if r.sdk["violation"] != {"label": "must-hold", "detail": "balance -1"}:
        die(f"{lang} fail: sdk.violation {r.sdk['violation']}")
    if r.site("before-fail")["held"] != 1 or r.site("after-fail")["evaluated"] != 0:
        die(f"{lang} fail: the run went on past the violation")
    last = log_ops(r)[-2:]
    if "patina_sdk" not in last[0] or "SdkViolation" not in last[1]:
        die(f"{lang} fail: the log does not end with the trap and the decision: {last}")

    r = run(f"01/{lang}-script", 5, cmd, "script",
            flags=["--buggify", "--fault", "point:point-a=500"])
    if r.cls != "ok":
        die(f"{lang} script: {r.cls} {r.outcome['message']}")
    u = r.site("unreached")
    if (u["evaluated"], u["held"]) != (0, 0) or not u["location"]:
        die(f"{lang} script: declared site unreached = {u}")
    if r.site("half-way")["held"] != 1 or r.site("never-holds")["held"] != 0:
        die(f"{lang} script: sometimes counts {r.site('half-way')} {r.site('never-holds')}")
    tables[lang], lines[lang] = r.table(), r.stdout
    print(f"{lang}: violation attributed; {len(tables[lang])} sites; {r.stdout.strip()}")

if len({repr(t) for t in tables.values()}) != 1:
    for lang, t in tables.items():
        print(lang, t)
    die("the four site tables differ")
if len(set(lines.values())) != 1 or "1" not in lines["c"].split()[0]:
    die(f"decisions differ, or no point fired: {lines}")
print("four languages: equal site tables and decisions")
