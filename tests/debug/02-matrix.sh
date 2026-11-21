# 2. `patina debug` across guests, in batch gdb; every read-only session ends as the recorded run.
#    C (stats-c, four threads, no debug info): stopped where the first thread is made, a
#    watchpoint on the shared count stops where a worker first writes it; gdb sees the threads.
#    Rust (quickstart): a breakpoint, step, finish, next and stepi, then on. Go (bank-go): a
#    breakpoint in the deposit handler (a goroutine) is hit twice, in the program's source;
#    stopped before an injected network fault (the supervisor's own event), the run goes on.
#    Python (journal-py): the backtrace reaches the interpreter's evaluation loop. Two nodes (a
#    key-value primary and backup, and the driver): stopped at the backup's last call, `patina
#    attach` moves gdb to another process and back to the stopped thread. A memory write leaves
#    the run at the first record where the session's events and the run's differ (`log events`
#    of both), and says it wrote memory. `--at call:NAME:K` names the K-th such call.
#@ tier=area budget=60
. "$(dirname "$0")/lib.inc"
E=$PATINA_GUESTS/examples
# seq_of RUNDIR PYTHON-EXPR: the sequence number of the first event (dict e) the expression holds for
seq_of() {
    "$PATINA" log events "$1" | python3 -I -c 'import json,sys
ev = [json.loads(l) for l in sys.stdin]
print(next(e["seq"] for e in ev if "seq" in e and eval(sys.argv[1])))' "$2"
}

# C: a watchpoint, and threads.
r=$RUNS/stats
prun "$r" --seed 1 -- "$E/stats"
at=$(seq_of "$r" 'e["type"] == "call" and e["name"].startswith("clone")')
cat >"$RUNS/c.gdb" <<'EOF'
watch *(long *)&stats
continue
python
print("FACT done", int(gdb.parse_and_eval("*(long *)&stats")))
print("FACT threads", len(gdb.selected_inferior().threads()))
end
delete
continue
EOF
session "$r" "$RUNS/c.gdb" --at "$at"
[ "$(fact "$r" done)" = 1 ] || die "C: the watchpoint stopped at count $(fact "$r" done)"
[ "$(fact "$r" threads)" -ge 2 ] || die "C: gdb sees $(fact "$r" threads) threads"
identical "$r"
echo "C: stopped where the first thread is made (seq $at); the watchpoint stopped at the first count, $(fact "$r" threads) threads; identical"

# Rust: breakpoints and stepping.
r=$RUNS/jobs
prun "$r" --seed 1 -- "$E/jobs"
cat >"$RUNS/rs.gdb" <<'EOF'
break main.rs:28
continue
python
print("FACT line", gdb.selected_frame().find_sal().line)
end
step
finish
next
stepi
delete
continue
EOF
# The program's first call, named the way --at names it.
name=$("$PATINA" log events "$r" | python3 -I -c 'import json,sys
print(next(e["name"] for e in map(json.loads, sys.stdin) if e["type"] == "call"))')
session "$r" "$RUNS/rs.gdb" --at "call:$name:1"
[ "$(fact "$r" line)" = 28 ] || die "Rust: the breakpoint stopped at line $(fact "$r" line)"
identical "$r"
echo "Rust: breakpoint at main.rs:28, step, finish, next, stepi; identical"
# --at call:NAME:K names the K-th.
n1=$(seq_of "$r" 'e["type"] == "call"')
[ "$(field "$r/debug/session.json" at)" = "$n1" ] || die "call:$name:1 is $(field "$r/debug/session.json" at), not $n1"

# A memory write: the run is left where the events first differ.
cat >"$RUNS/write.gdb" <<'EOF'
break main.rs:28
continue
set language c
set var *(unsigned long *)results.buf.inner.ptr.pointer.pointer = 7
delete
continue
EOF
session "$r" "$RUNS/write.gdb" --at "call:$name:1"
"$PATINA" log events "$r" >"$r.events"
"$PATINA" log events "$r/debug" >"$r.session-events"
m=$(python3 -I - "$r.events" "$r.session-events" <<'EOF'
import json, sys
a, b = ([json.loads(l) for l in open(p)] for p in sys.argv[1:])
a, b = ([e for e in x if "seq" in e] for x in (a, b))
i = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
a, b = a + [{"seq": 1 << 63}], b + [{"seq": 1 << 63}]
print(min(a[i]["seq"], b[i]["seq"]))
EOF
)
[ "$(field "$r/debug/session.json" left_at)" = "$m" ] || die "memory write: $(cat "$r/debug/session.json"), the events differ first at $m"
[ "$(field "$r/debug/session.json" did)" = '["memory"]' ] || die "memory write: $(cat "$r/debug/session.json")"
echo "memory write: left the run at seq $m, where the events first differ"

# Go: a breakpoint in the program's handler.
r=$RUNS/bank
prun "$r" --seed 1 --fault net-reset-permille=50 -- "$E/bank"
cat >"$RUNS/go.gdb" <<'EOF'
break main.main.func1
continue
continue
python
f = gdb.selected_frame()
print("FACT fn", f.name())
print("FACT file", f.find_sal().symtab.filename.endswith("main.go"))
end
delete
continue
EOF
session "$r" "$RUNS/go.gdb" --at call:write:1
[ "$(fact "$r" fn)" = main.main.func1 ] && [ "$(fact "$r" file)" = True ] || die "Go: the breakpoint stopped in $(fact "$r" fn)"
identical "$r"
echo "Go: a breakpoint in the deposit handler hit twice, in main.go; identical"
# The supervisor's own event: an injected fault; the supervisor parks, and gdb is on the
# process whose request it served.
printf 'bt 1\ncontinue\n' >"$RUNS/fault.gdb"
session "$r" "$RUNS/fault.gdb" --at fault:1
identical "$r"
echo "Go: stopped before the first injected fault (seq $(field "$r/debug/session.json" at)); identical"

# Python: the interpreter's frames.
r=$RUNS/journal
prun "$r" --seed 1 --mount "$E":/guest -- python3 /guest/journal.py
cat >"$RUNS/py.gdb" <<'EOF'
python
bt = gdb.execute("bt", to_string=True).splitlines()
print("FACT eval", int(any("_PyEval_EvalFrame" in l for l in bt)))
end
continue
EOF
session "$r" "$RUNS/py.gdb" --at sdk:journal-intact:1
[ "$(fact "$r" eval)" = 1 ] || die "Python: no evaluation loop in the backtrace: $(cat "$r.gdb")"
identical "$r"
echo "Python: the evaluation loop in the backtrace; identical"

# Nodes: the stop's process, another, and back.
r=$RUNS/kv
printf '[node.primary]\ncmd = ["python3", "/guest/kv.py", "primary"]\n[node.backup]\ncmd = ["python3", "/guest/kv.py", "backup"]\n' >"$RUNS/kv.toml"
[ -z "$TRAPS" ] || cat "$TRAPS" >>"$RUNS/kv.toml"
prun "$r" --seed 1 --config "$RUNS/kv.toml" --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/kv.py driver
at=$("$PATINA" log events "$r" | python3 -I -c 'import json,sys
print([e for e in map(json.loads, sys.stdin) if e["type"] == "call" and e.get("node") == "backup"][-1]["seq"])')
cat >"$RUNS/nodes.gdb" <<'EOF'
python
mine = gdb.selected_inferior().pid
print("FACT procs", len(procs()))
other = next(p for p in procs() if p[1] != mine)
gdb.execute("patina attach %d" % other[0])
print("FACT moved", int(gdb.selected_inferior().pid == other[1]))
gdb.execute("bt", to_string=True)
gdb.execute("patina attach %d" % S["pid"])
t = gdb.selected_thread()
print("FACT back", int(gdb.selected_inferior().pid == mine and t.ptid[1] == S["host_tid"]))
end
continue
EOF
session "$r" "$RUNS/nodes.gdb" --at "$at"
named=$(python3 -I -c 'import json,sys; print(sum(1 for p in json.load(open(sys.argv[1]))["procs"] if p["node"]))' "$r/debug/debug.json")
[ "$named" -ge 2 ] || die "nodes: $named processes with a node name: $(cat "$r/debug/debug.json")"
[ "$(fact "$r" procs)" -ge 3 ] || die "nodes: $(fact "$r" procs) processes"
[ "$(fact "$r" moved)" = 1 ] && [ "$(fact "$r" back)" = 1 ] || die "nodes: attach: $(cat "$r.gdb")"
identical "$r"
echo "nodes: $(fact "$r" procs) processes at seq $at; moved to another and back; identical"
