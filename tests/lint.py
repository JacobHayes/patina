"""tests/lint.py: the patterns behind flaky gate tests, in the scripts of every tier but evidence and
their helpers (tests/AREA/**/*.sh, *.inc, *.py; not evidence-*.sh, the evidence-only evidence/ and
bench/ directories, or guest sources). `mise run check` runs it.

  wall-clock  a value read from the host clock (date +%s, $SECONDS, time.time(), time.monotonic(),
              perf_counter, a run's wall_ms) compared against a bound. Printing it is fine.
  sleep       a sleep outside a loop: waiting a fixed time for something to happen. A sleep in a loop
              that re-checks a condition is a poll, and fine.
  seed        a literal --seed N whose finding (failure, violation, liveness, deadlock) is asserted
              within the next 10 lines. Search a seed range for the finding's signature instead.

Exempt: `# lint-allow: RULE — REASON` on the line or the line above; for a seed, also
`# reproducer: WHY THIS SEED`. Not detected (judged too noisy to catch statically): seeds passed
to helpers positionally, `timeout N` used as a bound, a finding asserted more than 10 lines after
its run, and clock values passed through files or function output. Prints FILE:LINE: RULE: text.
"""
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CLOCK = re.compile(r"\$\(\s*date \+%s|`date \+%s|\$\{?SECONDS\b|\btime\.time\(|\btime\.monotonic|perf_counter|wall_ms")
ASSIGN = re.compile(r"^\s*(?:local\s+)?(\w+)\s*(?:=|\+=|-=)(?!=)|^\s*def (\w+)|(\w+)\.append\(")
COMPARE = re.compile(r"-(?:lt|le|gt|ge)\b|\b(?:assert|if|elif|while|need)\b.*\s[<>]=?\s")
PRINT = re.compile(r"^\s*(?:echo|printf|print\(|f\.write\()")
SEED = re.compile(r"""--seed["',= ]+\d""")
FINDING = re.compile(r"\b(?:failure|violation|liveness|deadlock)\b")
SHSLEEP = re.compile(r"(?:^|[;&|(]|\bthen|\bdo|\belse)\s*(?P<s>sleep)\s")


def code(line):
    return "" if line.lstrip().startswith("#") else line.split(" #", 1)[0]


def allowed(lines, i, rule):
    near = lines[i] + "\n" + (lines[i - 1] if i else "")
    return bool(re.search(rf"# lint-allow: {rule} (?:—|-|:) *\S", near)
                or rule == "seed" and re.search(r"# reproducer: *\S", near))


def lint(path):
    lines = open(path).read().split("\n")
    found, tainted = [], set()
    for i, line in enumerate(lines):
        c = code(line)
        names = r"(?<![\w-])(?:" + "|".join(map(re.escape, tainted)) + r")\b" if tainted else None
        if CLOCK.search(c) or (names and re.search(names, c)):
            m = ASSIGN.search(c)
            if m:
                tainted.add(next(g for g in m.groups() if g))
            elif COMPARE.search(c) and not PRINT.search(c):
                found.append((i, "wall-clock"))
        if SEED.search(c) and any(FINDING.search(code(x)) for x in lines[i + 1:i + 11]):
            found.append((i, "seed"))
        if path.endswith((".sh", ".inc")):
            m = SHSLEEP.search(c)
            before = c[:m.start("s")] if m else ""
            depth = sum(len(re.findall(r"(?:^|[;\s])do(?:\s|$)", x)) - len(re.findall(r"(?:^|[;\s])done\b", x))
                        for x in lines[:i] + [before])
            if m and depth <= 0:
                found.append((i, "sleep"))
    if path.endswith(".py"):
        tree = ast.parse("\n".join(lines))
        loops = {id(n) for loop in ast.walk(tree) if isinstance(loop, (ast.For, ast.While)) for n in ast.walk(loop)}
        found += [(n.lineno - 1, "sleep") for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and ast.unparse(n.func) == "time.sleep" and id(n) not in loops]
    return [(i, r) for i, r in found if not allowed(lines, i, r)], lines


def main():
    bad = 0
    for area in sorted(os.listdir(HERE)):
        if area == "guests" or not os.path.isdir(os.path.join(HERE, area)):
            continue
        for d, subs, files in os.walk(os.path.join(HERE, area)):
            subs[:] = sorted(s for s in subs if s not in ("evidence", "bench", "guests", "attack"))
            for f in sorted(files):
                if f.endswith((".sh", ".inc", ".py")) and not f.startswith("evidence-"):
                    path = os.path.join(d, f)
                    found, lines = lint(path)
                    for i, rule in sorted(found):
                        print(f"{os.path.relpath(path, os.path.dirname(HERE))}:{i + 1}: {rule}: {lines[i].strip()}")
                    bad += len(found)
    if bad:
        print(f"lint: {bad} finding(s); fix them, or say why on the line: # lint-allow: RULE — REASON (tests/lint.py)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
