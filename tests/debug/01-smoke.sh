# 1. `patina debug` on the quickstart example (Rust; it panics): two sessions in batch gdb on the
#    helper the command writes. At the stop (explain's stop event), gdb's backtrace reaches the
#    program's main with its source line, through the runtime's signal frame; continuing, the
#    session is the recorded run. Calling a function in the program at the stop leaves the run
#    exactly there (session.json's left_at is the stop) and says it was a call. gdb killed
#    (SIGKILL) while it holds the stopped world: the run goes on and the session is the recorded
#    run. An event number past the run's end is refused before anything runs. SKIP without gdb
#    (PATINA_GDB or PATH) or where the host lets no debugger attach. x86_64 only in this
#    version; about 1 s.
#@ tier=quick budget=20 arch=x86_64
. "$(dirname "$0")/lib.inc"
r=$RUNS/jobs
prun "$r" --seed 1 -- "$PATINA_GUESTS/examples/jobs"

cat >"$RUNS/read.gdb" <<'EOF'
python
bt = gdb.execute("bt", to_string=True).splitlines()
print("FACT main", int(any(" jobs::main " in l and "main.rs:" in l for l in bt)))
print("FACT signal", int(any("<signal handler called>" in l for l in bt)))
end
continue
EOF
session "$r" "$RUNS/read.gdb"
[ "$(fact "$r" main)" = 1 ] || die "the backtrace does not reach main.rs: $(cat "$r.gdb")"
[ "$(fact "$r" signal)" = 1 ] || die "no signal frame in the backtrace: $(cat "$r.gdb")"
identical "$r"
at=$(field "$r/debug/session.json" at)
echo "read-only session at seq $at: identical"

cat >"$RUNS/call.gdb" <<'EOF'
print (int)getpid()
continue
EOF
session "$r" "$RUNS/call.gdb"
[ "$dst" != 0 ] || die "a session that called a function ended identical"
[ "$(field "$r/debug/session.json" left_at)" = "$at" ] || die "left_at: $(cat "$r/debug/session.json")"
[ "$(field "$r/debug/session.json" did)" = '["call"]' ] || die "did: $(cat "$r/debug/session.json")"
echo "a call at the stop: left the run at seq $at"

cat >"$RUNS/kill.gdb" <<'EOF'
python
import os, signal
os.kill(os.getpid(), signal.SIGKILL)
end
EOF
GDB_DIES=1 session "$r" "$RUNS/kill.gdb"
identical "$r"
echo "gdb killed at the stop: identical"

last=$("$PATINA" log events "$r" | python3 -I -c 'import json,sys
print(max(json.loads(l).get("seq", 0) for l in sys.stdin))')
rm -rf "${r:?}/debug"
st=0
timeout 60 "$PATINA" debug "$r" --no-gdb --at $((last + 1)) >"$r.past" 2>&1 || st=$?
[ "$st" != 0 ] && [ ! -e "$r/debug/debug.json" ] || die "--at past the end: exit $st: $(cat "$r.past")"
echo "--at $((last + 1)): refused"
