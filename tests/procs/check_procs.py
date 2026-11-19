"""check_procs.py MODE FILE: check the values a processes guest printed (behaviour, not wording: each
mode parses key=value fields and compares them with what the workload must produce)."""
import os
import re
import sys

mode, path = sys.argv[1], sys.argv[2]
text = open(path).read()
bad = []


def need(cond, what):
    if not cond:
        bad.append(what)


def kv(line):
    return dict(re.findall(r"(\S+?)=(\S+)", line))


if mode == "matrix":
    blocks = re.split(r"^== ", text, flags=re.M)[1:]
    fails = [l for l in blocks[-1].splitlines() if l.startswith("fail ")] if blocks else []
    need(len(blocks) == 24, f"{len(blocks)} started children, expected 24")
    for b in blocks:
        lines = b.splitlines()
        method, target = lines[0].split()
        f = {}
        argv = {}
        for l in lines[1:]:
            k, _, v = l.partition("=")
            if l.startswith("status "):
                f["status"] = l.split()[1]
            elif k.startswith("argv["):
                argv[int(k[5:-1])] = v
            else:
                f.setdefault(k, v)
        script = target.startswith("/guest/exec-files/")
        if target.endswith(".py"):
            need(os.path.basename(f.get("exe", "")).startswith("python3"), f"{method} {target}: exe {f.get('exe')}")
        elif target.endswith(".sh"):
            # dash reports what /proc/self/exe says in the child it starts (coreutils readlink).
            need(f.get("exe", "").endswith("/readlink"), f"{method} {target}: exe {f.get('exe')}")
        else:
            need(f.get("exe") == target, f"{method} {target}: exe {f.get('exe')}")
        want0 = target if script else "show-argv0"
        need(argv == {0: want0, 1: "one", 2: "two words"}, f"{method} {target}: argv {argv}")
        need(f.get("env") == f"{method}:{target}", f"{method} {target}: env {f.get('env')}")
        need(f.get("fds") == "0,1,2,5,", f"{method} {target}: fds {f.get('fds')}")
        need(f.get("hidden", "").startswith("-1,Bad file descriptor"), f"{method} {target}: hidden {f.get('hidden')}")
        need(f.get("status") == "0", f"{method} {target}: status {f.get('status')}")
    want = {"missing": "ENOENT", "noexec": "EACCES", "plain": "ENOEXEC", "directory": "EACCES", "longarg": "E2BIG", "bigvec": "E2BIG"}
    got = {}
    for l in fails:
        _, method, case, res = l.split(None, 3)
        got[(method, case)] = res
    for case, err in want.items():
        for method in ("fork", "vfork", "spawn"):
            need(got.get((method, case)) == err, f"{method} {case}: {got.get((method, case))}, expected {err}")
elif mode == "exit-order":
    kids = re.findall(r"^child (\d+) pid (\d+)$", text, re.M)
    reaped = re.findall(r"^reaped \S pid=(\d+) status=(\d+)$", text, re.M)
    tot = kv(re.search(r"^total .*$", text, re.M).group(0))
    need(len(kids) == 50 and len(reaped) == 50, f"{len(kids)} children wrote, {len(reaped)} reaped")
    want = {pid: str(int(i) % 256) for i, pid in kids}
    need(all(want.get(p) == s for p, s in reaped), "a reaped status is not the child's index")
    need(len(set(p for p, _ in reaped)) == 50, "a child reaped twice")
    need(tot.get("reaped") == "50" and tot.get("handler-reaped") == "50", f"totals {tot}")
    need(int(tot.get("bytes", 0)) == sum(len(f"child {i} pid {p}\n") for i, p in kids), "bytes read")
elif mode == "zombies":
    z = kv(re.search(r"^zombie .*$", text, re.M).group(0))
    w = kv(re.search(r"^waitpid=.*$", text, re.M).group(0))
    a = kv(re.search(r"^after reap .*$", text, re.M).group(0))
    g = kv(re.search(r"^grandchild .*$", text, re.M).group(0))
    need(z.get("kill0") == "0", f"kill(zombie, 0) = {z.get('kill0')}")
    need(w.get("waitpid") == z.get("pid") and w.get("exited") == "1" and w.get("status") == "42", f"waitpid {w}")
    need(a.get("kill0") == "-1" and a.get("errno") == "ESRCH", f"after reap {a}")
    need(g.get("ppid-after") == "1", f"orphan getppid {g.get('ppid-after')}")
elif mode == "xsig":
    need(re.search(r"^receiver \d+ exited=1 status=21$", text, re.M), "sibling kill")
    need(re.search(r"^group \d+: kill\(-pgid\)=0$", text, re.M), "kill(-pgid)")
    need(len(re.findall(r"^member \d+ pgid-was \d+ exited=1 status=31$", text, re.M)) == 3, "group members")
    need(re.search(r"^kill\(-pgid\) after: -1 ESRCH$", text, re.M), "kill of an empty group")
    need(re.search(r"^reader \d+ signaled=1 termsig=15 ", text, re.M), "SIGTERM default action")
    need(re.search(r"^ignorer \d+ code=2 status=9$", text, re.M), "SIGKILL of an ignorer (CLD_KILLED)")
else:
    sys.exit(f"unknown mode {mode}")
for b in bad:
    print("wrong:", b)
sys.exit(1 if bad else 0)
