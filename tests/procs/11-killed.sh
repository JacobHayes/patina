# 11. A guest process killed from outside the run (as the host's out-of-memory killer kills):
#     procs spinchild's child, computing alone, is sent SIGKILL from the host once it runs.
#     The run ends internal, stop killed, naming SIGKILL and the process, with the wait status
#     137 and signal 9 in result.json.
#@ tier=quick budget=20 slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/11-killed
rm -rf "${o:?}"
python3 -I - "$PATINA" "$o" "$PATINA_GUESTS" <<'PY'
import os, subprocess, sys, time
patina, out, guests = sys.argv[1:]
run = subprocess.Popen([patina, "run", "--seed", "1", "--timeout", "60", "--out", out,
                        "--mount", guests + ":/guest:copy", "--", "/guest/spinchild"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def tree(pid):
    """Every descendant of pid."""
    out = []
    try:
        for t in os.listdir(f"/proc/{pid}/task"):
            with open(f"/proc/{pid}/task/{t}/children") as f:
                for c in f.read().split():
                    out += [int(c)] + tree(int(c))
    except OSError:
        pass
    return out

def stat(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
        return s[s.index("(") + 1:s.rindex(")")], s[s.rindex(")") + 2]
    except OSError:
        return "", ""

# Poll until the child computes: two processes named spinchild, one running.
child = None
for _ in range(600):
    procs = [p for p in tree(run.pid) if stat(p)[0] == "spinchild"]
    running = [p for p in procs if stat(p)[1] == "R"]
    if len(procs) == 2 and running:
        child = running[0]
        break
    if run.poll() is not None:
        break
    time.sleep(0.1)
if child is None:
    run.kill()
    sys.exit("FAIL: the computing child never appeared")
os.kill(child, 9)
run.wait()
PY
[ "$(field "$o/result.json" outcome)/$(field "$o/result.json" stop)" = internal/killed ] ||
    die "spinchild killed: $(field "$o/result.json" outcome)/$(field "$o/result.json" stop): $(field "$o/result.json" message)"
[ "$(field "$o/result.json" guest.exit)/$(field "$o/result.json" guest.signal)" = 137/9 ] ||
    die "wait status: $(field "$o/result.json" guest)"
echo "killed from outside: $(field "$o/result.json" message | cut -c1-120)"
