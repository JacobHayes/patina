# Python compute points (`python3 -m patina`, sdk/python/patina.py; tests/guests/compute/py):
#  a. natively the runner is inert: the program's own output, and no sys.monitoring tool;
#  b. `cache` (check-then-act between two threads, no system call in the window): no failure
#     stock over seeds 1-40; with compute points at the default gap a failure in seeds 1-40,
#     whose first seed replays identical; the run names the interpreter with kind `line`;
#  c. `timer` (an ITIMER_REAL inside a loop with no system call): stock it never fires; with
#     compute points its handler runs within ten trap charges of 10 ms, one digest twice;
#     `oneline`: the exception the handler raises is caught by the frame's own `except`
#     in a one-line loop and in a comprehension (it arrives in a jump's hook);
#  d. `cpu` (two threads, loops with no system call): stock the second thread starts only
#     when the first has finished (one alternation); with compute points they alternate on
#     seeds 1-3, and seed 1 is identical over verify --runs 3 --vary cpu,aslr.
#@ tier=quick budget=20 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-python
mkdir -p "$o"
PY=/usr/bin/python3
PC=/guest/compute/py/pycompute.py
CP="--env PYTHONPATH=/guest/compute/py -- $PY -m patina"

echo "== a. native"
n=$(cd "$G/compute/py" && PYTHONPATH=. timeout 60 $PY -m patina pycompute.py cache 200) || die "a. native run: $n"
[ "$n" = "built 200 values for 200 keys" ] || die "a. native run printed $n"
m=$(cd "$G/compute/py" && timeout 60 $PY -I -c 'import sys; sys.path.insert(0, "."); import patina
print(patina.compute(), sys.monitoring.get_tool(3), sys.monitoring.get_tool(4))') || die "a. $m"
[ "$m" = "False None None" ] || die "a. natively compute() and the tool ids: $m"
echo "a. natively: the program's output; compute() off and no monitoring tool"

echo "== b. check-then-act"
sw() { # NAME [options] -- PROG...: a sweep of seeds 1-40 into $o/NAME
    sn=$1; shift
    "$PATINA" sweep --seeds 1..40 --out "$o/$sn" --mount "$G":/guest:copy "$@" >"$o/$sn.txt" 2>&1 || true
    [ -f "$o/$sn/report.json" ] || die "b. $sn: $(tail -3 "$o/$sn.txt")"
}
sw stock -- $PY "$PC" cache 200
grep -q '^outcomes: ok 40$' "$o/stock.txt" || die "b. stock: $(grep outcomes "$o/stock.txt")"
sw cache $CP "$PC" cache 200
grep -q '^outcomes: failure' "$o/cache.txt" || die "b. compute points: $(grep outcomes "$o/cache.txt")"
grep -q 'replayed: identical' "$o/cache.txt" || die "b. the first failing seed does not replay: $(grep -A1 '^failure' "$o/cache.txt")"
grep -q "^compute points: $PY (lines)" "$o/cache.txt" || die "b. no compute line naming $PY: $(grep 'compute points' "$o/cache.txt")"
echo "b. stock: $(grep outcomes "$o/stock.txt"); compute points: $(grep outcomes "$o/cache.txt"), $(grep -m1 'first: seed' "$o/cache.txt" | sed 's/^ *//')"

echo "== c. a timer in a loop"
prun "$o/t-stock" 1 -- $PY "$PC" timer 10 &
prun "$o/t-1" 1 $CP "$PC" timer 10 &
prun "$o/t-2" 1 $CP "$PC" timer 10 &
prun "$o/one" 1 $CP "$PC" oneline 5 &
wait
grep -q '^timer did not fire' "$o/t-stock/inc-0/stdout" || die "c. stock: $(cat "$o/t-stock/inc-0/stdout")"
for r in t-1 t-2 one; do [ "$(field "$o/$r/result.json" outcome)" = ok ] || die "c. $r: $(res "$o/$r")"; done
h=$(sed -n 's/.*handler_ns=//p' "$o/t-1/inc-0/stdout")
[ -n "$h" ] && [ "$h" -ge 10000000 ] && [ "$h" -le 10010000 ] || die "c. the handler ran at '$h' virtual ns: $(cat "$o/t-1/inc-0/stdout")"
lhs=$(field "$o/t-1/result.json" digest); rhs=$(field "$o/t-2/result.json" digest)
[ "$lhs" = "$rhs" ] || die "c. two runs of the timer differ"
[ "$(cat "$o/one/inc-0/stdout")" = "one-line loop: Stop caught
comprehension: Stop caught" ] || die "c. oneline: $(cat "$o/one/inc-0/stdout") $(tail -2 "$o/one/inc-0/stderr")"
echo "c. stock: $(cat "$o/t-stock/inc-0/stdout"); compute points: $(cat "$o/t-1/inc-0/stdout"), one digest twice; a one-line loop and a comprehension: Stop caught"

echo "== d. two CPU-bound threads"
alt() { sed -n 's/^cpu: [0-9]* marks, \([0-9]*\) alternations$/\1/p' "$1/inc-0/stdout"; }
prun "$o/c-stock" 1 -- $PY "$PC" cpu 50000 &
for s in 1 2 3; do prun "$o/c-$s" "$s" $CP "$PC" cpu 50000 & done
wait
[ "$(alt "$o/c-stock")" = 1 ] || die "d. stock: $(cat "$o/c-stock/inc-0/stdout")"
for s in 1 2 3; do
    a=$(alt "$o/c-$s")
    [ -n "$a" ] && [ "$a" -gt 1 ] || die "d. seed $s: $(res "$o/c-$s"); $(cat "$o/c-$s/inc-0/stdout")"
done
rm -rf "${o:?}/verify"
"$PATINA" verify --runs 3 --vary cpu,aslr --seed 1 --out "$o/verify" --mount "$G":/guest:copy \
    $CP "$PC" cpu 50000 >"$o/verify.txt" 2>&1 || true
grep -q '^identical: 3 runs' "$o/verify.txt" || die "d. cpu seed 1 under --vary cpu,aslr: $(tail -3 "$o/verify.txt")"
echo "d. stock: 1 alternation; compute points: $(alt "$o/c-1"), $(alt "$o/c-2"), $(alt "$o/c-3") alternations on seeds 1-3; seed 1 identical over 3 runs varying cpu and aslr"
