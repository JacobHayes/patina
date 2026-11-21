# 3. `patina debug` of runs with load-time points (the default): gdb passes the run's SIGTRAPs and refuses stepping.
#    go-race-stock (a stock Go build; its scheduling points are load-time plans): stopped at its
#    first scheduling point, a breakpoint in withdraw (a goroutine) is hit; stepi, next and step
#    are refused (an error in gdb, the run unchanged); on x86_64 a watchpoint on one round's
#    balance stops where a withdrawal takes it, and when that is a trampoline (an instruction
#    the plan moved) the frame under it is the original code's, in withdraw; on arm64 a
#    watchpoint is refused. The session is the recorded run.
#    stats-c stock (C, dynamic, PIE; on arm64 its text starts at file offset 0, a page the plan
#    maps over): a breakpoint in worker, kept, is hit by two threads in turn (continuing steps
#    over it); a conditional breakpoint is disabled (gdb would go on from it by itself with
#    the SIGTRAP passed); on x86_64 a watchpoint on the shared count stops in a worker.
#@ tier=area budget=60
. "$(dirname "$0")/lib.inc"
TRAPS="" # this script's runs are the default's
G=$PATINA_GUESTS
arm=0
m=$(uname -m)
[ "$m" != aarch64 ] || arm=1
seq_of() {
    "$PATINA" log events "$1" | python3 -I -c 'import json,sys
ev = [json.loads(l) for l in sys.stdin]
print(next(e["seq"] for e in ev if "seq" in e and eval(sys.argv[1])))' "$2"
}

r=$RUNS/gorace
prun "$r" --seed 1 --fault compute-gap=8 -- "$G/compute/go-race-stock"
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
EOF
if [ "$arm" = 1 ]; then
    cat >>"$RUNS/go.gdb" <<'EOF'
python
try:
    gdb.execute("watch *(long *)((char *)&'main.balance' + 72)")
    print("FACT refused-watch", 0)
except gdb.error:
    # Refused, not a bad expression: it reads, and no watchpoint was made.
    gdb.parse_and_eval("*(long *)((char *)&'main.balance' + 72)")
    print("FACT refused-watch", int(not gdb.breakpoints()))
end
continue
EOF
else
    cat >>"$RUNS/go.gdb" <<'EOF'
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
fi
session "$r" "$RUNS/go.gdb" --at "$at"
[ "$(fact "$r" tramps)" -gt 0 ] || die "points: no trampolines mapped"
[ "$(fact "$r" at)" = main.withdraw ] || die "points: the breakpoint stopped in $(fact "$r" at)"
for c in stepi next step; do [ "$(fact "$r" refused-$c)" = 1 ] || die "points: $c was not refused"; done
if [ "$arm" = 1 ]; then
    [ "$(fact "$r" refused-watch)" = 1 ] || die "points, arm64: a watchpoint was not refused"
    w="a watchpoint refused"
else
    [ "$(fact "$r" withdraw)" = 1 ] || die "points: the watchpoint's stop is not under withdraw: $(cat "$r.gdb")"
    w="the watchpoint under withdraw (in a trampoline: $(fact "$r" intramp))"
fi
identical "$r"
echo "points, Go: breakpoint in withdraw; stepping refused; $w; identical"

# C, dynamic and position-independent: the program's symbols and plan at its load address.
r=$RUNS/stats
prun "$r" --seed 1 -- "$G/examples/stats"
at=$(seq_of "$r" 'e["type"] == "call" and e["name"].startswith("clone")')
cat >"$RUNS/c.gdb" <<'EOF'
break worker
continue
python print("FACT first", gdb.selected_thread().num)
continue
python print("FACT second", gdb.selected_thread().num)
delete
break worker if 1
python print("FACT cond-enabled", int(gdb.breakpoints()[-1].enabled))
delete
EOF
[ "$arm" = 1 ] || cat >>"$RUNS/c.gdb" <<'EOF'
watch *(long *)&stats
continue
python
bt = gdb.execute("bt", to_string=True).splitlines()
print("FACT worker", int(any(" worker " in l for l in bt)))
end
delete
EOF
echo continue >>"$RUNS/c.gdb"
session "$r" "$RUNS/c.gdb" --at "$at"
first=$(fact "$r" first)
second=$(fact "$r" second)
[ -n "$first" ] && [ -n "$second" ] && [ "$first" != "$second" ] || die "points, C: the kept breakpoint stopped threads '$first' and '$second': $(cat "$r.gdb")"
# A conditional breakpoint would be gone on from by gdb itself, with the SIGTRAP passed: disabled.
[ "$(fact "$r" cond-enabled)" = 0 ] || die "points, C: a conditional breakpoint was left enabled"
[ "$arm" = 1 ] || [ "$(fact "$r" worker)" = 1 ] || die "points, C: the watchpoint's stop is not under worker: $(cat "$r.gdb")"
identical "$r"
echo "points, C: a kept breakpoint in worker hit by two threads$([ "$arm" = 1 ] || echo "; the watchpoint under worker"); identical"
