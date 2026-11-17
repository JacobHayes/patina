# 7. Every flag `patina --help --format json` lists for a command parses for that command (the
#    help and the parser read one table); a flag the table does not list for it is refused.
#    Each command's text help names each of its flags. --version prints a parseable version.
#@ tier=quick budget=5
. "$(dirname "$0")/lib.inc"
"$PATINA" --help --format json >"$RUNS/help.json"
python3 -I - "$PATINA" "$RUNS/help.json" <<'PY' || die "help and parser disagree"
import json, subprocess, sys
patina, h = sys.argv[1], json.load(open(sys.argv[2]))
def value(f):
    """A value of the flag's documented form: the first choice of A|B, else 1."""
    return [f["value"].split("|")[0] if "|" in f["value"] else "1"] if f["value"] else []
flags = {f["name"]: f for f in h["flags"]}
assert h["commands"] and flags
n = 0
for c in h["commands"]:
    text = subprocess.run([patina, c["name"], "--help"], capture_output=True, text=True, timeout=30)
    assert text.returncode == 0, (c["name"], text.stderr)
    for name in c["flags"]:
        f = flags[name]
        assert c["name"] in f["commands"], (c["name"], name)
        assert name in text.stdout, (c["name"], name, "not in text help")
        argv = [patina, c["name"], name] + value(f) + ["--help"]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, (argv, r.returncode, r.stderr)
        n += 1
    unknown = [patina, c["name"], "--no-such-flag", "--help"]
    r = subprocess.run(unknown, capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and "--no-such-flag" in r.stderr, (unknown, r.returncode, r.stderr)
    missing = [f for f in flags if f not in c["flags"]]
    for name in missing:
        argv = [patina, c["name"], name] + value(flags[name]) + ["--help"]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert r.returncode != 0, (argv, "accepted a flag the table does not list for it")
print(f"{n} (command, flag) pairs parse; {len(h['commands'])} commands")
PY
# --version: exit 0, `patina X.Y.Z[-pre]` (the release workflow reads it).
v=$("$PATINA" --version) || die "--version: exit $?"
echo "$v" | grep -Eq '^patina [0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "--version: $v"
echo "--version: $v"
