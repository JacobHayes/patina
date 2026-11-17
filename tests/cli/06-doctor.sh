# 6. `patina doctor` exits 0 on this host with every required check ok; with no bwrap on PATH
#    it exits with the `error` status and names the package that provides it. On arm64, a host
#    with 16 KiB pages (faked: PATINA_TEST_PAGE_SIZE) fails the page-size check, and the
#    launcher refuses a run with `error` before any sandbox.
#@ tier=quick budget=10
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

if [ "$(uname -m)" = aarch64 ]; then
    st=0
    timeout 60 env PATINA_TEST_PAGE_SIZE=16384 "$PATINA" doctor --format json >"$RUNS/pages.json" 2>&1 || st=$?
    [ "$st" = "$(exit_of error)" ] || die "16 KiB pages: doctor exit $st"
    python3 -I - "$RUNS/pages.json" <<'PY' || die "16 KiB pages: doctor json: $(cat "$RUNS/pages.json")"
import json, sys
bad = [c["name"] for c in json.load(open(sys.argv[1]))["checks"] if c["required"] and not c["ok"]]
assert bad == ["page size", "sandbox run"], bad
PY
    st=0
    timeout 60 env PATINA_TEST_PAGE_SIZE=16384 "$PATINA" run --out "$RUNS/pages-run" -- /bin/true >"$RUNS/pages-run.txt" 2>&1 || st=$?
    [ "$st" = "$(exit_of error)" ] || die "16 KiB pages: run exit $st: $(cat "$RUNS/pages-run.txt")"
    [ ! -e "$RUNS/pages-run" ] || die "16 KiB pages: the run started"
    echo "16 KiB pages: refused: $(cat "$RUNS/pages-run.txt")"
fi
