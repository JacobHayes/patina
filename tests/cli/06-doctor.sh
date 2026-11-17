# 6. `patina doctor` exits 0 on this host with every required check ok; with no bwrap on PATH
#    it exits with the `error` status and names the package that provides it.
#@ tier=quick budget=10 arch=x86_64
. "$(dirname "$0")/lib.inc"
st=0
timeout 60 "$PATINA" doctor --format json >"$RUNS/doctor.json" 2>"$RUNS/doctor.err" || st=$?
[ "$st" = 0 ] || die "doctor: exit $st: $(cat "$RUNS/doctor.json" "$RUNS/doctor.err")"
python3 -I - "$RUNS/doctor.json" <<'PY' || die "doctor json"
import json, sys
d = json.load(open(sys.argv[1]))
checks = d["checks"]
bad = [c for c in checks if c["required"] and not c["ok"]]
assert d["ok"] and checks and not bad, bad
print("doctor:", ", ".join(f"{c['name']} {'ok' if c['ok'] else 'missing'}" for c in checks))
PY
empty=$RUNS/empty-path
mkdir -p "$empty"
st=0
timeout 60 env PATH="$empty" "$PATINA" doctor >"$RUNS/nobwrap.txt" 2>&1 || st=$?
[ "$st" = "$(exit_of error)" ] || die "no bwrap: exit $st"
grep -q bubblewrap "$RUNS/nobwrap.txt" || die "no bwrap: package not named: $(cat "$RUNS/nobwrap.txt")"
echo "no bwrap: exit $st: $(grep -m1 bubblewrap "$RUNS/nobwrap.txt")"
