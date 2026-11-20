# `patina debug` of a counter-preemption run (race b, the race-hunting policy: every segment
# short, hundreds of preemptions): stopped at a preemption halfway, gdb passes the run's SIGTRAPs
# and refuses stepping (an error, the run unchanged); continuing, the session is the recorded run.
# SKIP without CAP_PERFMON, or without gdb or a host that lets a debugger attach.
#@ tier=area budget=60 arch=x86_64
. "$(dirname "$0")/lib.inc"
P=$(python3 -I -c 'import os, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from counters import ppatina
print(ppatina(required=False))')
case $P in SKIP:*) echo "$P"; exit 0 ;; esac
. "$(dirname "$0")/../debug/lib.inc"
PATINA=$P
r=$RUNS/races
prun "$r" --seed 1 --config "$("$PATINA_CFG" branches=hunt)" --mount "$PATINA_GUESTS":/guest:copy -- /guest/counters/races b
at=$("$PATINA" log events "$r" | python3 -I -c 'import json,sys
p = [e["seq"] for e in map(json.loads, sys.stdin) if e["type"] == "preempt"]
assert len(p) >= 10, len(p)
print(p[len(p) // 2])')
cat >"$RUNS/br.gdb" <<'EOF'
python
try:
    gdb.execute("stepi")
    print("FACT refused", 0)
except gdb.error:
    print("FACT refused", 1)
end
continue
EOF
session "$r" "$RUNS/br.gdb" --at "$at"
[ "$(fact "$r" refused)" = 1 ] || die "stepi was not refused"
identical "$r"
echo "branches: stopped at preemption $at; stepi refused; identical"
