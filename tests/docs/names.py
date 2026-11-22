"""tests/docs/names.py: the docs name only what the patina under test has; the guide mentions
every command, fault class and outcome it has; the skill names nothing that can change.

The patina binary is the source of truth (`patina --help --format json`). The docs are the
guide's pages (docs/guide/*.md, which `patina guide` prints), README.md, examples/README.md and
ARCHITECTURE.md. ./check docs runs their command blocks (transcripts.py); this checks the names
around them, which no command runs:

- In code (`sh` fences, `$` lines of `text` fences, inline code spans), each `patina COMMAND
  ...` names a command; `log` a word of that command's usage; each option, one the command takes
  (in the guide, also an inline span that starts with an option: one some command takes);
  `--fault KEY=V` and a span `KEY=V`, a fault key; `--faults A,B`, fault classes (or `all`); an
  option whose value is a list of words, one of them. Anywhere, `[TABLE] KEY` names a
  patina.toml key. Upper-case words are placeholders and are not checked.
- A table whose first column is `Outcome` lists outcomes with their exit status.
- Test inputs (`PATINA_TEST_*`, AGENTS.md) appear in neither `--help` nor these files.
- Every command appears as `patina COMMAND`, every class as a `--faults` value and every outcome
  in an Outcome table somewhere in the guide: a new one fails here until the guide says when
  to use it.
- The skill (skills/patina/SKILL.md, which `patina skill` writes) is a pointer that must not go
  stale: frontmatter `name: patina` and a description; no code block; its only code spans are
  `patina guide`, `patina doctor` and `patina skill` (with a placeholder argument); and nowhere an
  option, a fault key or a patina.toml table or key.

An existence check of names, not of wording. Prints each name it does not know, with its place.
"""
import json
import os
import re
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
GUIDE = os.path.join(REPO, "docs", "guide")
SKILL = os.path.join(REPO, "skills", "patina", "SKILL.md")
DOCS = ["README.md", "examples/README.md", "ARCHITECTURE.md"]
TOML = re.compile(r"\[(run|faults|sched|sweep)\] ([a-z][a-z-]*)")
FENCE = re.compile(r"^```(\w*)\s*$")
SPAN = re.compile(r"`([^`]+)`")
# The commands `patina debug` adds to gdb, which the docs show as `patina procs` and so on.
GDB = {"procs", "attach", "where"}
KEY = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$")
PLACEHOLDER = re.compile(r"[A-Z]")


def vocabulary(patina):
    text = subprocess.run([patina, "--help", "--format", "json"], check=True,
                          stdout=subprocess.PIPE, text=True).stdout
    d = json.loads(text)
    v = {"test_inputs": "PATINA_TEST_" in text,
         "commands": {c["name"]: c for c in d["commands"]},
         "flags": {f["name"]: f for f in d["flags"]},
         "keys": {k["name"] for k in d["faults"]["keys"]},
         "classes": {p["name"] for p in d["faults"]["classes"]} | {"all"},
         "outcomes": {o["name"]: o["exit"] for o in d["outcomes"]},
         "config": {(c["table"], c["key"]) for c in d["config"]},
         "short": {}}
    for f in d["flags"]:
        for s in re.findall(r"\balso (-[a-zA-Z]) ", f["help"]):
            v["short"][s] = f["name"]
    # A command's second words (log tree): the lower-case words of its usage.
    v["words"] = {n: set(re.findall(r"(?<![-\w])([a-z]+)(?![-\w])", c["usage"])) - {"patina", n}
                  for n, c in v["commands"].items()}
    return v


def code(path):
    """(line number, text, kind) of each piece of code in a doc: `cmd` for a command line
    of a fence, `span` for an inline code span of prose (which may cross a line); and the rows of
    its tables."""
    lines = open(path).read().split("\n")
    out, rows, fence, cont, prose = [], [], None, "", []
    for i, line in enumerate(lines, 1):
        m = FENCE.match(line)
        if m and fence is None:
            fence = m.group(1)
            continue
        if line.rstrip() == "```" and fence is not None:
            fence = None
            continue
        if fence is not None:
            if fence == "sh" or (fence == "text" and (line.startswith("$ ") or cont)):
                text = line[2:] if fence == "text" and line.startswith("$ ") else line
                cont += text
                if text.endswith("\\"):
                    cont = cont[:-1]
                    continue
                out.append((i, cont, "cmd"))
                cont = ""
            continue
        if line.startswith("|"):
            rows.append((i, [c.strip() for c in line.strip().strip("|").split("|")]))
        prose.append((i, line))
    # Spans per paragraph: a span may continue on the next line, never past a blank line or a fence.
    para = []
    for i, line in prose + [(0, "")]:
        if line.strip() and (not para or i == para[-1][0] + 1):
            para.append((i, line))
            continue
        text = "\n".join(l for _, l in para)
        for m in SPAN.finditer(text):
            out.append((para[0][0] + text.count("\n", 0, m.start()), m.group(1).replace("\n", " "), "span"))
        para = [(i, line)] if line.strip() else []
    return out, rows


def commands(text):
    """The `patina ...` invocations in a line of code, each as its words up to the end of that
    command (a pipe, `;`, `&&`, `)`)."""
    for m in re.finditer(r"(?:^|[\s;(&|])(?<!-m )patina\s+(?=\S)", text):
        rest = re.split(r"\s(?:\||;|&&|\|\|)\s|\)", text[m.end():])[0]
        try:
            yield shlex.split(rest)
        except ValueError:
            yield rest.split()


def check_words(where, cmd, words, v, bad, seen):
    """Check one command's words: cmd is its name (None: an option span of no known command)."""
    i = 0
    while i < len(words):
        w = words[i]
        i += 1
        if w == "--":
            return
        if not re.match(r"--[a-z]|-[a-z]$", w) or PLACEHOLDER.search(w.split("=")[0]):
            continue
        name, eq, inline = w.partition("=")
        name = v["short"].get(name, name)
        f = v["flags"].get(name)
        if f is None:
            bad.append(f"{where}: no option {name}")
            continue
        if cmd is not None and cmd not in f["commands"]:
            bad.append(f"{where}: patina {cmd} takes no {name}")
            continue
        value = (f["by_command"].get(cmd) or f)["value"] if cmd else f["value"]
        if not value or (value.startswith("[=") and not eq):  # a switch, or an optional value not given
            continue
        if eq:
            arg = inline
        elif i < len(words):
            arg = words[i]
            i += 1
        else:
            continue
        check_value(where, name, value, arg, v, bad, seen)


def check_value(where, name, value, arg, v, bad, seen):
    if PLACEHOLDER.search(arg):
        return
    if name == "--fault":
        if arg != "help":  # --fault help lists the keys
            check_key(where, arg, v, bad)
    elif name == "--faults":
        # CLASS[,CLASS][@NODE,...]: the scope after `@` names nodes.
        for p in arg.split("@")[0].split(","):
            seen["classes"].add(p)
            if p not in v["classes"]:
                bad.append(f"{where}: no fault class {p}")
    elif "|" in value and arg.replace("\\|", "|") != value and all(re.fullmatch(r"[a-z]+", a) for a in value.split("|")):
        for a in arg.split(","):
            if a not in value.split("|"):
                bad.append(f"{where}: {name} takes {value}, not {a}")


def check_key(where, kv, v, bad):
    key = kv.split("=")[0]
    if key.startswith("buggify:") and "buggify:LABEL" in v["keys"]:
        return
    if key not in v["keys"]:
        bad.append(f"{where}: no fault key {key}")


def check_file(path, v, bad, seen, doc=False):
    """Check the names in one file, noting in seen the commands, classes and outcomes it names.
    A doc other than the guide also shows other tools' options in code spans: there only the
    options of a `patina` command are checked."""
    rel = os.path.relpath(path, REPO)
    for no, line in enumerate(open(path), 1):
        if "PATINA_TEST_" in line:
            bad.append(f"{rel}:{no}: a test input (PATINA_TEST_*) in a user doc: AGENTS.md lists them")
        for m in TOML.finditer(line):
            t, k = m.groups()
            if (t, k) not in v["config"] and not (t == "faults" and k in v["keys"]):
                bad.append(f"{rel}:{no}: no patina.toml key [{t}] {k}")
    pieces, rows = code(path)
    for no, text, kind in pieces:
        where = f"{rel}:{no}"
        found = False
        for words in commands(text):
            found = True
            if not words or PLACEHOLDER.search(words[0]):
                continue
            if words[0] in ("--version", "--help") or words[0].startswith("__") \
                    or words[0] in GDB:
                continue
            cmd = words[0]
            if cmd not in v["commands"]:
                bad.append(f"{where}: no command patina {cmd}")
                continue
            seen["commands"].add(cmd)
            if cmd == "ctl":  # its words are the control call's (`kill NAME`)
                continue
            rest = words[1:]
            if cmd == "log" and rest and not rest[0].startswith("-") \
                    and not PLACEHOLDER.search(rest[0]):
                if rest[0] not in v["words"][cmd]:
                    bad.append(f"{where}: no patina {cmd} {rest[0]} "
                               f"(usage: {v['commands'][cmd]['usage']})")
                rest = rest[1:]
            check_words(where, cmd, rest, v, bad, seen)
        if found or kind != "span" or (doc and text.startswith("-")):
            continue
        if text.startswith("-") and not text.startswith("--- "):
            try:
                words = shlex.split(text)
            except ValueError:
                words = text.split()
            check_words(where, None, words, v, bad, seen)
        elif "=" in text and " " not in text and KEY.match(text.split("=")[0]):
            check_key(where, text, v, bad)
    header, prev = None, 0
    for no, cells in rows:
        if no != prev + 1:
            header = None
        prev = no
        if cells[0] == "Outcome":
            header = cells
            continue
        m = re.fullmatch(r"`([a-z-]+)`", cells[0])
        if header is None or not m:
            continue
        name = m.group(1)
        seen["outcomes"][name] = f"{rel}:{no}"
        if name not in v["outcomes"]:
            bad.append(f"{rel}:{no}: no outcome {name}")
        elif "Exit" in header and cells[header.index("Exit")] != str(v["outcomes"][name]):
            bad.append(f"{rel}:{no}: outcome {name} exits {v['outcomes'][name]}, "
                       f"the doc says {cells[header.index('Exit')]}")


def check_skill(v, bad):
    """The skill names nothing an option, key or outcome table holds, so it cannot drift."""
    rel = os.path.relpath(SKILL, REPO)
    text = open(SKILL).read()
    head = re.match(r"---\n(.*?)\n---\n", text, re.S)
    meta = dict(l.split(":", 1) for l in head.group(1).split("\n") if ":" in l) if head else {}
    if meta.get("name", "").strip() != "patina" or not meta.get("description", "").strip():
        bad.append(f"{rel}: frontmatter needs name: patina and a description")
    pieces, _ = code(SKILL)
    for no, line in enumerate(text.split("\n"), 1):
        if FENCE.match(line):
            bad.append(f"{rel}:{no}: a code block: the skill points to patina guide, which shows commands")
        for m in re.finditer(r"(?<![\w-])--?[a-zA-Z][\w-]*", line):
            bad.append(f"{rel}:{no}: an option, {m.group(0)}: options belong in patina guide")
        for k in v["keys"] | {k for t, k in v["config"] if "-" in k}:
            name = k.split(":")[0] + (":" if ":" in k else "")
            if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", line):
                bad.append(f"{rel}:{no}: the key {name}: keys belong in patina guide")
        if re.search(r"\[(run|faults|sched|sweep|node)\b", line):
            bad.append(f"{rel}:{no}: a patina.toml table: config belongs in patina guide")
    for no, span, kind in pieces:
        if kind == "span" and not re.fullmatch(r"patina (guide|doctor|skill)( [A-Z]+)?", span):
            bad.append(f"{rel}:{no}: `{span}`: the skill names only `patina guide`, `patina doctor` "
                       "and `patina skill`")


def main():
    patina = os.environ.get("PATINA")
    if not patina:
        sys.exit("names.py: PATINA is not set: run it through ./check docs")
    v = vocabulary(patina)
    guide = sorted(os.path.join(GUIDE, f) for f in os.listdir(GUIDE) if f.endswith(".md"))
    bad = ["patina --help names a test input (PATINA_TEST_*): AGENTS.md lists them"] if v["test_inputs"] else []
    seen = {"commands": set(), "classes": set(), "outcomes": {}}
    for path in guide:
        check_file(path, v, bad, seen)
    for d in DOCS:
        check_file(os.path.join(REPO, d), v, bad, {"commands": set(), "classes": set(), "outcomes": {}},
                   doc=True)
    check_skill(v, bad)
    for c in sorted(set(v["commands"]) - seen["commands"]):
        bad.append(f"docs/guide: patina {c} is not mentioned (a new command?): say when to use it")
    for p in sorted(v["classes"] - {"all"} - seen["classes"]):
        bad.append(f"docs/guide: --faults {p} is not mentioned (a new class?): say when to use it")
    for o in sorted(set(v["outcomes"]) - set(seen["outcomes"])):
        bad.append(f"docs/guide: outcome {o} is in no Outcome table (a new outcome?): say what it means")
    for b in bad:
        print("FAIL: " + b)
    print(f"== names: {len(guide)} guide pages, {len(DOCS)} docs and the skill; {len(seen['commands'])} commands, "
          f"{len(seen['classes'])} classes, {len(seen['outcomes'])} outcomes named in the guide; "
          f"{len(bad)} unknown or missing")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
