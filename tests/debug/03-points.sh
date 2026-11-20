# 3. `patina debug` of `--preempt points` runs: gdb passes the run's SIGTRAPs and refuses stepping.
#    go-race-stock (a stock Go build; its scheduling points are load-time plans): stopped at its
#    first scheduling point, a breakpoint in withdraw (a goroutine) is hit; stepi, next and step
#    are refused (an error in gdb, the run unchanged); a watchpoint on one round's balance stops
#    where a withdrawal takes it, and when that is a trampoline (an instruction the plan moved)
#    the frame under it is the original code's, in withdraw; the session is the recorded run.
#    stats-c stock (C, dynamic, PIE): a watchpoint on the shared count stops in a worker.
#@ tier=area budget=60 arch=x86_64
. "$(dirname "$0")/lib.inc"
G=$PATINA_GUESTS
seq_of() {
    "$PATINA" log events "$1" | python3 -I -c 'import json,sys
ev = [json.loads(l) for l in sys.stdin]
print(next(e["seq"] for e in ev if "seq" in e and eval(sys.argv[1])))' "$2"
}

r=$RUNS/gorace
prun "$r" --seed 1 --preempt points --fault compute-gap=8 -- "$G/compute/go-race-stock"
# The run's first scheduling point: before the goroutines start.
at=$(seq_of "$r" 'e["type"] == "preempt"')
cat >"$RUNS/go.gdb" <<'EOF'
set language c
python
print("FACT tramps", len(TRAMP))
end
break main.withdraw
continue
python
print("FACT at", gdb.selected_frame().name())
for c in ("stepi", "next", "step"):
    try:
        gdb.execute(c)
        print("FACT refused-" + c, 0)
    except gdb.error:
        print("FACT refused-" + c, 1)
end
delete
watch *(long *)((char *)&'main.balance' + 72)
continue
python
bt = gdb.execute("bt", to_string=True).splitlines()
print("FACT withdraw", int(any(" main.withdraw " in l for l in bt)))
print("FACT intramp", int(tramp_orig(int(gdb.newest_frame().pc())) is not None))
end
delete
continue
EOF
session "$r" "$RUNS/go.gdb" --at "$at"
[ "$(fact "$r" tramps)" -gt 0 ] || die "points: no trampolines mapped"
[ "$(fact "$r" at)" = main.withdraw ] || die "points: the breakpoint stopped in $(fact "$r" at)"
for c in stepi next step; do [ "$(fact "$r" refused-$c)" = 1 ] || die "points: $c was not refused"; done
[ "$(fact "$r" withdraw)" = 1 ] || die "points: the watchpoint's stop is not under withdraw: $(cat "$r.gdb")"
identical "$r"
echo "points, Go: breakpoint in withdraw; stepping refused; the watchpoint under withdraw (in a trampoline: $(fact "$r" intramp)); identical"

# C, dynamic and position-independent: the program's symbols and plan at its load address.
r=$RUNS/stats
prun "$r" --seed 1 --preempt points -- "$G/examples/stats"
at=$(seq_of "$r" 'e["type"] == "call" and e["name"].startswith("clone")')
cat >"$RUNS/c.gdb" <<'EOF'
watch *(long *)&stats
continue
python
bt = gdb.execute("bt", to_string=True).splitlines()
print("FACT worker", int(any(" worker " in l for l in bt)))
end
delete
continue
EOF
session "$r" "$RUNS/c.gdb" --at "$at"
[ "$(fact "$r" worker)" = 1 ] || die "points, C: the watchpoint's stop is not under worker: $(cat "$r.gdb")"
identical "$r"
echo "points, C: the watchpoint under worker; identical"
