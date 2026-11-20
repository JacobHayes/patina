"""tests/docs/transcripts.py [FILE[:NAME]...]: the command transcripts in the user docs are true.
(`./check docs` runs all; given FILE or FILE:NAME, those blocks, each after the blocks of its dir
before it.)

This is a wording check by design, of our own docs against our own tool: the one sanctioned
exception to "never assert wording". A transcript that shows what a command prints must show what
it prints now; two releases existed only to correct ones that did not.

Docs: README.md, docs/GUIDE.md, examples/README.md, ARCHITECTURE.md. A transcript is a fenced
block with an HTML comment right before it (invisible when rendered):

    <!-- transcript NAME
    dir: /tmp/upcase
    setup: cp "$GUESTS/examples/upcase" .
    exit: 0 1
    -->

Two forms. A `text` fence of `$ COMMAND` lines (a line ending in `\\` continues on the next),
each followed by its output; or a `sh` fence of commands followed by a `text` fence that is the
output of its last command (the others' output is not shown; they must still succeed). Keys:

  dir      the directory the doc shows the commands in (default /tmp/patina). Blocks of one file
           with the same dir share it, in order: a later block sees what an earlier one left
           (patina-out). It is made under a scratch root R; R is removed from the output and put
           in front of the dir in the commands, so the doc shows the paths a reader would see.
           Each starts with `sdk`, `tests` and each entry of `examples` linked to the checkout's,
           as the docs' commands run from the repository root; the checkout's path in the
           output is the dir.
  setup    a shell line (repeatable) run in the dir first, with REPO, GUESTS (the built guests)
           and PATINA set: it stands in for what the doc leaves to the reader.
  skip     N: the first N commands of a `sh` fence are not run (a clone, a build); setup stands in.
  exit     the exit status of each command in order (default 0 for each).
  command  a `text` fence with no `$` line is an excerpt of this command's output.
  exact-only  REASON: the block runs only where the numbers are compared exactly (below): what
           it shows depends on one seed's run (a pinned `--seed`, a run directory of a seed).
  arch     MACHINE: the block runs only on this `uname -m` (a feature of one architecture);
           elsewhere it is listed, not run.
  release-only  REASON: the block runs only in the release tier (`./check release`): a sweep
           of many runs, too slow for the landing gate; elsewhere it is listed, not run.

The docs' numbers (seeds, counts, digests, sequence numbers) are one kind of host's: they depend
on the architecture, the CPU, the kernel and the host's libraries and interpreters that a program
loads, as docs/GUIDE.md "Hosts" says. The checker prints the kind of this host, a hash of those;
where it is REFERENCE below, every line is compared exactly. Elsewhere (another architecture, the
hosted CI runners, whose CPUs vary from run to run) every number is N in both sides first, so the
lines, labels, flags, outcome names, rerun lines and exit statuses must still match, and the
`exact-only` blocks are listed, not run. After writing the numbers on another kind of host, put
its hash in REFERENCE.

`<!-- no-run NAME: REASON -->` before a block says it cannot run here (a second host, a VM,
root, the network); every run lists those blocks. A `text` fence holding a `$ patina` or
`$ ./check` line, or a `sh` fence directly followed by a `text` fence, that has neither comment
is an error.

Compared line by line, exactly, after these, applied to both sides:
  `...` alone on a line   any lines (none included)
  `(0.2s, 8 jobs)`        wall time and job count of a sweep
  `306.8 KiB kept in`     bytes a sweep kept (paths and the build's identity are in them)
  `again in 0.0s`         a recheck's wall time
  `cpu 23` in verify      the host CPU a verify run was placed on
  `(seed 1: ...seed-1)`   in a `new:` line, the run of the new group that finished first
and a sweep's progress line (`sweep: 3/8 runs, ...`, printed every 10 s of wall time when not on
a terminal) is dropped from the command's output; where the numbers are not compared: a 16-digit hash is H, every number N, and a word after
a number loses a plural `s` (`1 group`, `3 groups`).
Trailing spaces are ignored. A mismatch prints the file, the block, its line and a diff.
"""
import difflib
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DOCS = ["README.md", "docs/GUIDE.md", "examples/README.md", "ARCHITECTURE.md"]
FENCE = re.compile(r"^```(\w*)\s*$")
COMMENT = re.compile(r"^<!--\s*(transcript|no-run)\s+([A-Za-z0-9_.-]+)(:?)(.*)$")
HOST = [
    (re.compile(r"\(\d+\.\d+s, \d+ jobs\)"), "(T, J jobs)"),
    (re.compile(r"\b\d+(\.\d+)? (B|KiB|MiB|GiB) kept in\b"), "SIZE kept in"),
    (re.compile(r"\bagain in \d+\.\d+s\b"), "again in T"),
    (re.compile(r"^(run \d+: )cpu \d+ "), r"\1cpu C "),
    # A sweep announces a new group with the first of its runs to finish: with several jobs,
    # not always the same one (the group's `first:` below is its lowest seed).
    (re.compile(r"^(new.*   \(seed )\S+(: patina replay \S+/seed-)\S+\)$"), r"\1S\2S)"),
]
# A sweep's status line, printed every 10 s of wall time off a terminal: on a slow host, also
# in a doc's command.
PROGRESS = re.compile(r"^sweep: \d+/\d+ runs, .* running, \d+\.\d+ runs/s, ")
# The kind of host the docs' numbers are from (the hash host_kind() prints).
REFERENCE = "3a30419beb30fdd4"


class Block:
    def __init__(self, path, line, name):
        self.path, self.line, self.name = path, line, name
        self.dir, self.setup, self.skip, self.exits, self.command = "/tmp/patina", [], 0, None, None
        self.cmds = []      # [(command, expected output lines, their doc line numbers)]
        self.no_run = self.exact_only = self.arch = self.release_only = None

    def where(self):
        return f"{self.path}:{self.line} [{self.name}]"


def fences(lines):
    """(start index, info, body lines, end index) of each fenced block."""
    out, i = [], 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if m:
            j = i + 1
            while j < len(lines) and lines[j].rstrip() != "```":
                j += 1
            out.append((i, m.group(1), lines[i + 1:j], j))
            i = j + 1
        else:
            i += 1
    return out


def split_dollar(body, first):
    """A `$` transcript whose first line is doc line FIRST: [(command, output lines, their doc
    line numbers)]."""
    cmds, cur = [], None
    for k, line in enumerate(body):
        if line.startswith("$ ") and not (cur and cur[0].endswith("\\")):
            cur = [line[2:], [], []]
            cmds.append(cur)
        elif cur and cur[0].endswith("\\") and not cur[1]:
            cur[0] = cur[0] + "\n" + line
        elif cur:
            cur[1].append(line)
            cur[2].append(first + k)
        else:
            return None
    return [tuple(c) for c in cmds]


def sh_commands(body):
    cmds, cur = [], ""
    for line in body:
        if not cur and (not line.strip() or line.lstrip().startswith("#")):
            continue
        cur = cur + ("\n" if cur else "") + line
        if not line.endswith("\\"):
            cmds.append(cur)
            cur = ""
    return cmds


def parse(path):
    """The blocks of one doc, and the errors in its marking."""
    with open(os.path.join(REPO, path)) as f:
        lines = f.read().split("\n")
    fs = fences(lines)
    blocks, errors, names = [], [], set()
    used = set()
    for k, (start, info, body, end) in enumerate(fs):
        if start in used:
            continue
        # The comment right before the fence (blank lines allowed between).
        c = start - 1
        while c >= 0 and not lines[c].strip():
            c -= 1
        head = None
        if c >= 0 and lines[c].rstrip().endswith("-->"):
            o = c
            while o >= 0 and not lines[o].startswith("<!--"):
                o -= 1
            head = (o, lines[o:c + 1]) if o >= 0 else None
        nxt = fs[k + 1] if k + 1 < len(fs) else None
        follows = nxt is not None and info == "sh" and nxt[1] == "text" and all(
            not l.strip() for l in lines[end + 1:nxt[0]])
        looks = follows or (info == "text" and any(l.startswith(("$ patina", "$ ./check")) for l in body))
        m = COMMENT.match(head[1][0]) if head else None
        if not m:
            if looks:
                errors.append(f"{path}:{start + 1}: a transcript with no `<!-- transcript NAME -->` "
                              "or `<!-- no-run NAME: REASON -->` before it")
            continue
        kind, name = m.group(1), m.group(2)
        b = Block(path, start + 1, name)
        if name in names:
            errors.append(f"{b.where()}: the name is used twice in {path}")
        names.add(name)
        if kind == "no-run":
            b.no_run = (m.group(4).replace("-->", "").strip()
                        + " " + " ".join(l.strip() for l in head[1][1:]).replace("-->", "")).strip()
            if not m.group(3) or not b.no_run:
                errors.append(f"{b.where()}: no-run needs a reason: `<!-- no-run NAME: REASON -->`")
            if follows:
                used.add(nxt[0])
            blocks.append(b)
            continue
        for kv in head[1][1:]:
            kv = kv.strip()
            if kv == "-->" or not kv:
                continue
            key, _, val = kv.partition(":")
            val = val.strip()
            if key == "dir":
                b.dir = val
            elif key == "setup":
                b.setup.append(val)
            elif key == "skip":
                b.skip = int(val)
            elif key == "exit":
                b.exits = [int(x) for x in val.split()]
            elif key == "exact-only":
                b.exact_only = val
            elif key == "arch":
                b.arch = val
            elif key == "release-only":
                b.release_only = val
            elif key == "command":
                b.command = val
            else:
                errors.append(f"{b.where()}: unknown key {key!r}")
        if not b.dir.startswith("/"):
            errors.append(f"{b.where()}: dir must be absolute")
        if b.command is not None:
            n = list(range(start + 2, start + 2 + len(body)))
            b.cmds = [(b.command, ["..."] + body + ["..."], [start + 2] + n + [end + 1])]
        elif info == "text":
            b.cmds = split_dollar(body, start + 2)
            if not b.cmds:
                errors.append(f"{b.where()}: a `text` transcript must start with a `$ COMMAND` line")
                continue
        elif info == "sh" and follows:
            cs = sh_commands(body)[b.skip:]
            if not cs:
                errors.append(f"{b.where()}: no command left to run")
                continue
            n = list(range(nxt[0] + 2, nxt[0] + 2 + len(nxt[2])))
            b.cmds = [(c, None, None) for c in cs[:-1]] + [(cs[-1], nxt[2], n)]
            used.add(nxt[0])
        else:
            errors.append(f"{b.where()}: a transcript is a `text` fence of `$` lines, or a `sh` fence "
                          "followed by a `text` fence")
            continue
        if b.exits is not None and len(b.exits) != len(b.cmds):
            errors.append(f"{b.where()}: exit lists {len(b.exits)} statuses for {len(b.cmds)} commands")
            continue
        blocks.append(b)
    return blocks, errors


def norm(lines, structure):
    out = []
    for line in lines:
        line = line.rstrip()
        if PROGRESS.match(line):
            continue
        if line != "...":
            for pat, rep in HOST:
                line = pat.sub(rep, line)
            if structure:
                line = re.sub(r"\b[0-9a-f]{16}\b", "H", line)
                line = re.sub(r"\d+", "N", line)
                line = re.sub(r"\bN (\w+?)s\b", r"N \1", line)
        out.append(line)
    return out


def host_kind(guests):
    """A hash of what the docs' numbers depend on besides the repository: the machine, the kernel
    release, the CPU's model and features, the compilers that build the examples, and the host
    files the examples load (the C library and the loader, Python)."""
    h = hashlib.sha256()
    def add(*argv):
        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        h.update(r.stdout.encode())
    h.update(platform.machine().encode() + platform.release().encode())
    with open("/proc/cpuinfo") as f:
        first = f.read().split("\n\n")[0]
    h.update("\n".join(l for l in first.split("\n") if l.split(":")[0].strip() in (
        "vendor_id", "cpu family", "model", "model name", "flags", "CPU implementer", "CPU part",
        "CPU variant", "Features")).encode())
    for tool in ("cc", "clang"):
        add(tool, "--version")
    files = {os.path.realpath("/usr/bin/python3")}
    for exe in ("jobs", "acklog"):
        r = subprocess.run(["ldd", os.path.join(guests, "examples", exe)], stdout=subprocess.PIPE, text=True)
        files |= {os.path.realpath(w) for w in r.stdout.split() if w.startswith("/")}
    for p in sorted(files):
        with open(p, "rb") as f:
            h.update(p.encode() + hashlib.sha256(f.read()).digest())
    return h.hexdigest()[:16]


def match(exp, act):
    """Whether exp (with `...` lines matching any lines) matches act; and exp with each matched
    `...` replaced by the lines it took (index -1 in exp), as (line, index in exp) pairs, for a
    diff that shows only what differs."""
    segs, cur = [], []
    for i, line in enumerate(exp):
        if line == "...":
            segs.append(cur)
            cur = []
        else:
            cur.append((line, i))
    segs.append(cur)
    text = lambda seg: [l for l, _ in seg]
    rest = lambda k: [p for t in segs[k:] for p in [("...", -1)] + t]
    shown = list(segs[0])
    if act[:len(segs[0])] != text(segs[0]):
        return False, shown + rest(1)
    pos = len(segs[0])
    for k, s in enumerate(segs[1:], 1):
        found = None
        if k == len(segs) - 1:
            if len(act) - len(s) >= pos and act[len(act) - len(s):] == text(s):
                found = len(act) - len(s)
        else:
            for i in range(pos, len(act) - len(s) + 1):
                if act[i:i + len(s)] == text(s):
                    found = i
                    break
        if found is None:
            return False, shown + [("...", -1)] + s + rest(k + 1)
        shown += [(l, -1) for l in act[pos:found]] + s
        pos = found + len(s)
    if len(segs) == 1 and pos != len(act):
        return False, shown
    return True, shown


def first_difference(shown, act, nos):
    """The doc line number of the first difference, the doc's line there and the command's."""
    lines = [l for l, _ in shown]
    op = next(o for o in difflib.SequenceMatcher(None, lines, act, autojunk=False).get_opcodes()
              if o[0] != "equal")
    _, i1, _, j1, _ = op
    k = i1
    while k > 0 and (k >= len(shown) or shown[k][1] < 0):
        k -= 1
    no = nos[shown[k][1]] if shown and shown[k][1] >= 0 else nos[0] if nos else 0
    if k < i1 or i1 >= len(shown):
        no += 1
    doc = lines[i1] if i1 < len(lines) else "(nothing more)"
    cmd = act[j1] if j1 < len(act) else "(nothing more)"
    return no, doc, cmd


def run_scene(blocks, guests, patina, exact):
    """Run one dir's blocks in order; return [(block, ok, report lines)]."""
    root = tempfile.mkdtemp(prefix="pdocs.", dir="/tmp")
    try:
        d = root + blocks[0].dir
        os.makedirs(d)
        for n in ("sdk", "tests"):
            os.symlink(os.path.join(REPO, n), os.path.join(d, n))
        # examples/ holds a link to each example, so a setup can put a build in place of one.
        os.mkdir(os.path.join(d, "examples"))
        for n in os.listdir(os.path.join(REPO, "examples")):
            os.symlink(os.path.join(REPO, "examples", n), os.path.join(d, "examples", n))
        env = dict(os.environ, REPO=REPO, GUESTS=guests, PATINA=patina, LC_ALL="C.UTF-8",
                   PATH=os.path.dirname(patina) + ":/usr/local/bin:/usr/bin:/bin")
        results = []
        for b in blocks:
            structure = not exact
            report = []
            for s in b.setup:
                r = subprocess.run(["bash", "-euo", "pipefail", "-c", s], cwd=d, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if r.returncode:
                    report.append(f"setup `{s}` exited {r.returncode}: {r.stdout.strip()[-400:]}")
            exits = b.exits or [0] * len(b.cmds)
            for (cmd, exp, nos), want in zip(b.cmds, exits):
                if report:
                    break
                r = subprocess.run(["bash", "-o", "pipefail", "-c", cmd.replace(b.dir, d)], cwd=d, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                out = r.stdout.decode(errors="replace").replace(root, "").replace(REPO, b.dir).split("\n")
                if out and out[-1] == "":
                    out.pop()
                if r.returncode != want:
                    report.append(f"`$ {cmd}`: exit status {r.returncode}, the doc says {want}")
                    report += ["    " + l for l in out[-15:]]
                    break
                if exp is None:
                    continue
                e, a = norm(exp, structure), norm(out, structure)
                ok, shown = match(e, a)
                if not ok:
                    no, doc, got = first_difference(shown, a, nos)
                    report.append(f"`$ {cmd}`: the output differs" + (" (numbers as N)" if structure else ""))
                    report.append(f"{b.path}:{no}: the doc:     {doc}")
                    report.append(f"{' ' * len(f'{b.path}:{no}')}  the command: {got}")
                    report += ["    " + l.rstrip() for l in difflib.unified_diff(
                        [l for l, _ in shown], a, "the doc", "the command", lineterm="", n=2)]
                    break
            results.append((b, not report, report))
            if report:
                # A later block of this dir builds on this one: it would only repeat the failure.
                for later in blocks[blocks.index(b) + 1:]:
                    results.append((later, False, [f"not run: {b.name} before it in {b.dir} failed"]))
                break
        return results
    finally:
        for dp, dn, _ in os.walk(root):
            for n in dn:
                p = os.path.join(dp, n)
                if not os.path.islink(p):
                    os.chmod(p, 0o755)
        shutil.rmtree(root)


def main():
    want = sys.argv[1:]
    patina = os.environ.get("PATINA")
    guests = os.environ.get("PATINA_GUESTS")
    if not patina or not guests:
        sys.exit("transcripts.py: PATINA and PATINA_GUESTS are not set: run it through ./check docs")
    blocks, errors = [], []
    for path in DOCS:
        bs, es = parse(path)
        blocks += bs
        errors += es
    for e in errors:
        print("FAIL: " + e)
    if want:
        # A block named alone runs after the blocks before it in its dir, which it builds on.
        picked = [b for b in blocks if any(w == b.path or w == f"{b.path}:{b.name}" for w in want)]
        blocks = [b for b in blocks if any(p.path == b.path and p.dir == b.dir and p.line >= b.line
                                           and not b.no_run for p in picked) or b in picked]
    kind = host_kind(guests)
    exact = kind == REFERENCE
    if exact:
        print(f"== host kind {kind}: the docs' numbers are this kind's; compared exactly")
    else:
        print(f"== host kind {kind}, the docs' numbers are {REFERENCE}'s: numbers compared as N; "
              "exact-only blocks not run")
    norun = [b for b in blocks if b.no_run]
    machine = platform.machine()
    release = os.environ.get("CHECK_TIER") == "release"
    held = [b for b in blocks if not b.no_run and ((b.exact_only and not exact) or (b.arch and b.arch != machine)
                                                   or (b.release_only and not release))]
    runnable = [b for b in blocks if not b.no_run and b not in held]
    scenes = {}
    for b in runnable:
        scenes.setdefault((b.path, b.dir), []).append(b)
    with ThreadPoolExecutor(max_workers=int(os.environ.get("DOCS_JOBS", "2"))) as ex:
        results = [r for rs in ex.map(lambda s: run_scene(s, guests, patina, exact), scenes.values()) for r in rs]
    failed = [r for r in results if not r[1]]
    for b, ok, report in sorted(results, key=lambda r: (r[0].path, r[0].line)):
        print(f"{'PASS' if ok else 'FAIL'} {b.where()} {len(b.cmds)} commands")
        for line in report:
            print("    " + line)
    for title, bs, why in (("no-run", norun, lambda b: b.no_run),
                           ("exact-only, release-only or another architecture's, not run here", held,
                            lambda b: (not exact and b.exact_only)
                            or (b.arch and b.arch != machine and f"{b.arch} only") or b.release_only)):
        print(f"== {title} ({len(bs)}):")
        for b in bs:
            print(f"   {b.where()}: {why(b)}")
    per = {}
    for b, _, _ in results:
        per[b.path] = per.get(b.path, 0) + 1
    print(f"== transcripts: {len(results)} run ({', '.join(f'{p} {n}' for p, n in per.items())}), "
          f"{'exactly' if exact else 'numbers as N'}; {len(failed)} failed; {len(held)} not run here; "
          f"{len(norun)} no-run; {len(errors)} marking errors")
    if not results and not want:
        print("FAIL: no transcript ran")
        return 1
    return 1 if failed or errors else 0

if __name__ == "__main__":
    sys.exit(main())
