# 5. A run from ./patina.toml with no flags equals the same run given only flags: run.json is
#    equal apart from the directory each was made in, and so are the digests. An unknown key
#    is refused, naming it.
#@ tier=quick budget=5
. "$(dirname "$0")/lib.inc"
# Each run in its own directory: the program and a mounted data directory next to it.
for k in file flags; do
    mkdir -p "$RUNS/$k/data"
    cp "$PATINA_GUESTS/hello-static" "$RUNS/$k/prog"
    echo hello >"$RUNS/$k/data/x"
done
cat >"$RUNS/file/patina.toml" <<'EOF'
[run]
cmd = ["./prog", "a"]
cpus = 3
env = { CLI_TEST = "1" }
mounts = ["./data:/data"]
time-limit = 500
timeout = 50

[faults]
fs-error-permille = 5
EOF
st=0
(cd "$RUNS/file" && PATINA_SEED=3 timeout 60 "$PATINA" run) >"$RUNS/file.txt" 2>&1 || st=$?
[ -f "$RUNS/file/patina-out/run-3/result.json" ] || die "file: no result.json ($(tail -2 "$RUNS/file.txt"))"
(cd "$RUNS/flags" && timeout 60 "$PATINA" run --seed 3 --cpus 3 --env CLI_TEST=1 --mount data:/data \
    --time-limit 500 --timeout 50 --fault fs-error-permille=5 -- ./prog a) >"$RUNS/flags.txt" 2>&1 || true
[ -f "$RUNS/flags/patina-out/run-3/result.json" ] || die "flags: no result.json ($(tail -2 "$RUNS/flags.txt"))"
python3 -I - "$RUNS" <<'PY' || die "run.json differs"
import json, os, sys
runs = sys.argv[1]
def load(k):
    t = open(f"{runs}/{k}/patina-out/run-3/run.json").read()
    for r in (os.path.realpath(runs), runs):
        t = t.replace(f"{r}/{k}/", "DIR/")
    return json.loads(t)
a, b = load("file"), load("flags")
if a != b:
    print(json.dumps(a, indent=1, sort_keys=True))
    print(json.dumps(b, indent=1, sort_keys=True))
    sys.exit(1)
PY
a=$(field "$RUNS/file/patina-out/run-3/result.json" digest) b=$(field "$RUNS/flags/patina-out/run-3/result.json" digest)
[ "$a" = "$b" ] || die "digests differ: $a $b"
echo "patina.toml and flags: equal run.json, digest $a"
# An unknown key.
mkdir -p "$RUNS/bad"
printf '[run]\ncpus = 2\nno-such-key = 1\n' >"$RUNS/bad/patina.toml"
st=0
(cd "$RUNS/bad" && timeout 60 "$PATINA" run --seed 1 -- /bin/true) >"$RUNS/bad.txt" 2>&1 || st=$?
[ "$st" = "$(exit_of error)" ] || die "unknown key: exit $st"
grep -q 'no-such-key' "$RUNS/bad.txt" || die "unknown key not named: $(cat "$RUNS/bad.txt")"
[ ! -e "$RUNS/bad/patina-out" ] || die "unknown key: a run was made"
echo "unknown key: exit $st: $(cat "$RUNS/bad.txt")"
