# 5. A run from ./patina.toml with no flags equals the same run given only flags (from the same
#    directory: a program runs from where it is): run.json is equal, and so are the digests. The
#    file's [machine.main] run is the flags run's command after --.
#    An unknown key is refused, naming it.
#@ tier=quick budget=5
. "$(dirname "$0")/lib.inc"
# The program, a mounted data directory, the configuration file, and one with only the
# settings no flag carries (cpus, time-limit) that the flags run names instead.
d=$RUNS/same
mkdir -p "$d/data"
cp "$PATINA_GUESTS/hello-static" "$d/prog"
echo hello >"$d/data/x"
printf '[run]\ncpus = 3\ntime-limit = 500\n' >"$d/rest.toml"
cat >"$d/patina.toml" <<'EOF'
[run]
cpus = 3
env = { CLI_TEST = "1" }
mounts = ["./data:/data"]
time-limit = 500
timeout = 50

[machine.main]
run = ["./prog", "a"]

[faults]
fs-error-permille = 5
EOF
st=0
(cd "$d" && timeout 60 "$PATINA" run --seed 3 --out file) >"$RUNS/file.txt" 2>&1 || st=$?
[ -f "$d/file/result.json" ] || die "file: no result.json ($(tail -2 "$RUNS/file.txt"))"
(cd "$d" && timeout 60 "$PATINA" run --config rest.toml --out flags --seed 3 --env CLI_TEST=1 \
    --mount data:/data --timeout 50 --fault fs-error-permille=5 -- ./prog a) >"$RUNS/flags.txt" 2>&1 || true
[ -f "$d/flags/result.json" ] || die "flags: no result.json ($(tail -2 "$RUNS/flags.txt"))"
python3 -I - "$d" <<'PY' || die "run.json differs"
import json, sys
a, b = (json.load(open(f"{sys.argv[1]}/{k}/run.json")) for k in ("file", "flags"))
if a != b:
    print(json.dumps(a, indent=1, sort_keys=True))
    print(json.dumps(b, indent=1, sort_keys=True))
    sys.exit(1)
PY
a=$(field "$d/file/result.json" digest) b=$(field "$d/flags/result.json" digest)
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
