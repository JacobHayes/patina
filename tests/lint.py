"""tests/lint.py: the patterns behind flaky gate tests, in the scripts of every tier but evidence and
their helpers (tests/AREA/**/*.sh, *.inc, *.py; not evidence-*.sh, the evidence-only evidence/ and
bench/ directories, or guest sources). `mise run check` runs it.

  wall-clock  a value read from the host clock (date +%s, $SECONDS, time.time(), time.monotonic(),
              perf_counter, a run's wall_ms) compared against a bound. Printing it is fine.
  sleep       a sleep outside a loop: waiting a fixed time for something to happen. A sleep in a loop
              that re-checks a condition is a poll, and fine.
  seed        a literal --seed N whose finding (failure, violation, liveness, deadlock) is asserted
              within the next 10 lines. Search a seed range for the finding's signature instead.

The shell scripts run strict (tests/run.py: bash -euo pipefail, inherit_errexit; every other
script says so on its own line). What strict mode cannot see, in every shell script of the
repository but the guests' sources (tests/AREA/**, evidence included; check, scripts/, testbeds/,
install.sh, examples/checks/):

  or-true     `|| true` or `|| :` after a pipeline or a captured value ($(...)): a tool that
              crashed reads as "nothing found". Write the expected failure out (`st=0; cmd ||
              st=$?`, `if ! cmd`), or count with a tool that does not fail on zero (awk).
  negated-pipe  a pipeline whose success is the failure (`! A | grep -q x || die`, `A | grep x &&
              die`): when A fails, the check passes. Keep A's output (a file, a variable), then grep it.
  test-subst  a test that passes when the command in it fails: [ -z "$(A)" ], [ "$(A)" != X ],
              [ "$(A)" = "$(B)" ] (both fail: both empty), [ "$(A | wc -l)" = 0 ] (or -le, -lt):
              [ ] does not see A's status, even under pipefail. Assign it first (n=$(A)), where
              strict mode sees it.
  subst-status  local/export/readonly/declare x=$(cmd): the builtin's status hides cmd's.
  cd          an unguarded cd in a function: a caller's `if f`/`f ||` turns -e off inside it.
  rm-var      rm -r of a path that starts with a variable without ${VAR:?}: empty, it is /.
  set-off     set +e, set +u, set +o pipefail, shopt -u inherit_errexit.
  plain-sh    a script or snippet started with `sh` (dash: not strict, no pipefail); use bash.
  strict-line a script run on its own without its strict line: `set -euo pipefail` and `shopt -s
              inherit_errexit` under bash; `set -eu` and no pipefail (dash on the CI runners
              refuses it) under #!/bin/sh, which only install.sh and examples/checks/ use (a
              checker without -e says why: exit 1 is its finding, so its commands exit 2 themselves).

Exempt: `# lint-allow: RULE — REASON` on the line or the line above; for a seed, also
`# reproducer: WHY THIS SEED`. Not detected (judged too noisy to catch statically): seeds passed
to helpers positionally, `timeout N` used as a bound, a finding asserted more than 10 lines after
its run, and clock values passed through files or function output; `|| true` after one command
(mostly `patina run ... || true`, whose outcome is read from result.json next), a function whose
failure a caller tests (`f || die`: -e is off inside f, so f must return its own status), a
reader that stops early (head, grep -q, awk exit) before a writer that is still writing (pipefail
then fails it: red, not silent), and backquotes. Prints FILE:LINE: RULE: text.
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


def shape(text):
    """TEXT with quoted characters as "x" and comments and here-document bodies as spaces (lines
    and lengths kept), and the $(...) depth of every character."""
    out, depth, stack = [], [], []  # stack: "sub" (a $(...)), "par" (a paren inside one), '"'
    i, n, sq, heredocs = 0, len(text), False, []
    while i < n:
        c, top = text[i], (stack[-1] if stack else None)
        d = stack.count("sub")
        if c == "\n" and heredocs and not sq and top != '"':
            out.append(c); depth.append(d); i += 1
            while heredocs:  # skip the bodies, up to each terminator line
                word, strip = heredocs.pop(0)
                while i < n:
                    j = text.find("\n", i); j = n if j < 0 else j
                    line = text[i:j]
                    out.append(" " * (j - i) + ("\n" if j < n else "")); depth += [d] * (j - i + (j < n))
                    i = j + 1
                    if (line.lstrip("\t") if strip else line) == word:
                        break
            continue
        if sq:
            sq = c != "'"
            out.append(c if c in "'\n" else "x"); depth.append(d); i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append("xx" if top == '"' else c + text[i + 1]); depth += [d, d]; i += 2
            continue
        if top == '"':
            if c == '"':
                stack.pop(); out.append(c)
            elif text.startswith("$(", i):
                stack.append("sub"); out.append("$("); depth.append(d); i += 1
            else:
                out.append(c if c == "\n" else "x")
            depth.append(d); i += 1
            continue
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;"):
            j = text.find("\n", i); j = n if j < 0 else j
            out.append(" " * (j - i)); depth += [d] * (j - i); i = j
            continue
        if c == "'":
            sq = True
        elif c == '"':
            stack.append('"')
        elif text.startswith("$(", i) and not text.startswith("$((", i):
            stack.append("sub"); out.append("$("); depth += [d, d + 1]; i += 2
            continue
        elif c == "(" and top in ("sub", "par"):
            stack.append("par")
        elif c == ")" and top in ("sub", "par"):
            stack.pop()
        elif c == "<" and top != '"':
            m = re.match(r"<<(-?)\s*['\"]?(\w+)['\"]?", text[i:])
            if m and not text.startswith("<<<", i):
                heredocs.append((m.group(2), m.group(1) == "-"))
        out.append(c); depth.append(d); i += 1
    return "".join(out), depth


SEP = re.compile(r";|&&|\|\||\n|\b(?:then|do|else)\b|^")
ORTRUE = re.compile(r"\|\|\s*(?:true|:)(?=\s*(?:$|[;)&|}]|\bfi\b|\bdone\b|\bthen\b))")
PIPE = re.compile(r"(?<![|>])\|(?![|&])")
SUBST_STATUS = re.compile(r"(?:^|[;&|{(]|\bthen|\bdo|\belse)\s*(?:local|export|readonly|declare|typeset)\s+(?:-\w+\s+)*\w+=\"?\$\(")
FUNC = re.compile(r"(?:^|[;\s])\w+\s*\(\)\s*\{")
CD = re.compile(r"(?:^|[;&|{(]|\bthen|\bdo|\belse)\s*cd(?:\s|$)")
RM = re.compile(r"(?<![\w-])rm\s+(?:-\w+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+([^;&|)\n]*)")
TEST = re.compile(r"(?<![\w\]\[])\[ (?:[^]\n]|\$\([^\n]*?\))*? \]")
VACUOUS = re.compile(r"-z \"?\$\(|\$\([^\n]*\)\"? != |!= \"?\$\(|\$\((?![(]|printf |echo )[^\n]*\)\"? = \"?\$\((?![(]|printf |echo )")
VACUOUS_NUM = re.compile(r"\)\"? (?:-le|-lt|-ne|(?:=|-eq) \"?0\"? )")
NEGATED = re.compile(r"(?:^|[;&|(]|\b(?:then|do|else|if|while|until)\b)[ \t]*(?P<neg>!)[ \t]|&&\s*(?:die|fail)\b", re.M)
SETOFF = re.compile(r"\bset\s+\+(?:[a-z]*[eu][a-z]*\b|o\s+(?:pipefail|errexit|nounset)\b)|\bshopt\s+-u\s+inherit_errexit\b")
PLAINSH = re.compile(r"(?:^|[;&|(]|\b(?:then|do|else|exec)\b|\bxargs\b[^;&|'\"]*?)\s*(?:\w+=\S*\s+)*\bsh\s+(?=-c\b|[\"$\w./])")


def segment(masked, depth, p):
    """The command that `||` at P guards: back to the last separator at P's depth."""
    starts = [m.end() for m in SEP.finditer(masked, 0, p)
              if depth[m.start()] == depth[p] and not (m.group() == "\n" and re.search(r"(?:\\|\||&&)\s*$", masked[:m.start()]))]
    q = starts[-1] if starts else 0
    return masked[q:p], q


def shell_lint(path, own):
    """The strict-mode findings in a shell script; OWN: it runs as its own process."""
    text = open(path).read()
    lines = text.split("\n")
    masked, depth = shape(text)
    line_of = lambda p: text.count("\n", 0, p)
    found = []
    for m in ORTRUE.finditer(masked):
        p = m.start()
        seg, q = segment(masked, depth, p)
        piped = any(depth[q + k.start()] == depth[p] for k in PIPE.finditer(seg))
        captured = depth[p] > 0 or re.match(r"\s*(?:\w+=\S*\s+)*\w+=\"?\$\(", seg)
        if piped or captured:
            found.append((line_of(p), "or-true"))
    # A pipeline whose success is the failure: `! A | grep x || die`, `A | grep x && die`.
    for m in NEGATED.finditer(masked):
        p = m.end() if m.group("neg") else m.start()
        if m.group("neg"):
            end = re.compile(r";|&&|\|\||\n|\bthen\b").search(masked, p)
            seg, q = masked[p:end.start() if end else len(masked)], p
        else:
            seg, q = segment(masked, depth, p)
        pipes = [k for k in PIPE.finditer(seg) if depth[q + k.start()] == depth[p]]
        if pipes and not re.match(r"\s*(?:echo|printf)\s", seg):
            found.append((line_of(p), "negated-pipe"))
    # A test that a failure passes: [ -z "$(A)" ], [ "$(A)" != X ], [ "$(A | wc -l)" = 0 ] (or
    # -le, -lt): [ ] does not see A's status.
    for m in TEST.finditer(masked):
        t, base = m.group(), m.start()
        subs = [k.start() for k in re.finditer(r"\$\(", t)]
        if not subs:
            continue
        counted = [k for k in PIPE.finditer(t) if depth[base + k.start()] > depth[base]
                   and re.match(r"\s*(?:wc|grep -c|awk)\b", t[k.end():])]
        if VACUOUS.search(t) or counted and VACUOUS_NUM.search(t):
            found.append((line_of(base), "test-subst"))
    mlines = masked.split("\n")
    for i, line in enumerate(mlines):
        if i and mlines[i - 1].rstrip().endswith("\\"):
            line = "\\" + line  # a continued line: its first word is no command
        if SUBST_STATUS.search(line):
            found.append((i, "subst-status"))
        if SETOFF.search(line):
            found.append((i, "set-off"))
        if PLAINSH.search(line):
            found.append((i, "plain-sh"))
        m = RM.search(lines[i])
        if m:
            for arg in m.group(1).split():
                if re.match(r"\"?\$(?:\w|\{\w+(?!:\?)[^}]*\})", arg) and not arg.lstrip('"').startswith("${") or \
                        re.match(r"\"?\$\{\w+(?!:\?)[}#%/:-]", arg):
                    found.append((i, "rm-var"))
                    break
    # cd in a function body (brace depth counted on the masked text).
    fdepth = 0
    for i, line in enumerate(masked.split("\n")):
        start = FUNC.search(line)
        if fdepth or start:
            for m in CD.finditer(line):
                rest = line[m.end():]
                if not re.match(r"[^;&|)]*(?:\|\||&&)", rest):
                    found.append((i, "cd"))
            if start and not fdepth:
                fdepth = line[start.end() - 1:].count("{") - line[start.end() - 1:].count("}")
            else:
                fdepth += len(re.findall(r"(?:^|\s)\{(?:\s|$)", line)) - len(re.findall(r"(?:^|[\s;])\}", line))
            fdepth = max(fdepth, 0)
    if own:
        first = lines[0] if lines else ""
        if "bash" in first:
            if not re.search(r"^set -euo pipefail\b", text, re.M) or not re.search(r"\bshopt -s inherit_errexit\b", text):
                found.append((0, "strict-line"))
        elif "pipefail" in masked or not re.search(r"^set -eu\b", text, re.M):
            m = re.search(r"^set -u\b", text, re.M)  # a checker: exit 1 is its finding, not set -e's
            found.append((text.count("\n", 0, m.start()) if m and "pipefail" not in masked else 0, "strict-line"))
    return [(i, r) for i, r in sorted(set(found)) if not allowed(lines, i, r)], lines


def shell_scripts():
    """(path, runs as its own process) of every shell script but the guests' sources."""
    root = os.path.dirname(HERE)
    out = [(os.path.join(root, p), True) for p in ("check", "install.sh", "tests/guests.sh")]
    for d in ("scripts", "examples/checks", "testbeds"):
        for dd, subs, files in os.walk(os.path.join(root, d)):
            subs[:] = sorted(s for s in subs if s != "target")
            for f in sorted(files):
                path = os.path.join(dd, f)
                with open(path, "rb") as fh:
                    head = fh.readline()
                if f.endswith(".sh") or head.startswith(b"#!") and re.search(rb"\b(?:ba)?sh\b", head):
                    out.append((path, True))
    for area in sorted(os.listdir(HERE)):
        if area == "guests" or not os.path.isdir(os.path.join(HERE, area)):
            continue
        for d, subs, files in os.walk(os.path.join(HERE, area)):
            subs[:] = sorted(s for s in subs if s not in ("guests", "attack", "__pycache__"))
            for f in sorted(files):
                if f.endswith((".sh", ".inc")):
                    out.append((os.path.join(d, f), f.endswith(".sh") and d != os.path.join(HERE, area)))
    return out


def main():
    bad = 0
    root = os.path.dirname(HERE)
    for path, own in shell_scripts():
        found, lines = shell_lint(path, own)
        for i, rule in found:
            print(f"{os.path.relpath(path, root)}:{i + 1}: {rule}: {lines[i].strip()}")
        bad += len(found)
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
