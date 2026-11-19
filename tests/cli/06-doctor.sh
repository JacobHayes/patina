# 6. `patina doctor` exits 0 on this host with every required check ok. The AppArmor profile it
#    prints admits this binary by its canonical path and nothing else, and, where the parser is
#    installed, parses (offline, nothing loaded). On arm64, a host with 16 KiB pages (faked:
#    PATINA_TEST_PAGE_SIZE) fails the page-size check, and the launcher refuses a run with
#    `error` before any sandbox.
#@ tier=quick,release budget=10
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
exe=$(realpath "$PATINA")
timeout 60 "$PATINA" doctor --print-apparmor-profile >"$RUNS/profile" || die "profile: exit $?"
grep -qF "profile patina \"$exe\" flags=(unconfined)" "$RUNS/profile" || die "profile: not for $exe: $(cat "$RUNS/profile")"
grep -qx '  userns,' "$RUNS/profile" || die "profile: no userns rule"
for parser in /usr/sbin/apparmor_parser /sbin/apparmor_parser; do
    if [ -x "$parser" ]; then
        "$parser" -Q -K -T "$RUNS/profile" || die "profile: $parser rejects it"
        echo "profile: parsed by $parser"
        break
    fi
done
echo "profile: for $exe"

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
