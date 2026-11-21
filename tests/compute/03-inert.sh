# Compute points change nothing they should not:
#  a. every compute guest runs natively (its hooks go inert) with its normal output;
#  b. a stock program's run under [sched] preempt = "traps" (no load-time points, whose cell
#     is the same) has no `compute` in result.json, no SDK call and no compute record
#     in its log, and its clock moves only by the trap charge across a loop;
#  c. the rebuilt loop at compute-gap=0 moves the clock by at least one event per iteration;
#  d. a program that writes 0, -1 and a huge value into its cell repeats (one digest twice);
#     one that unmaps the cell's page ends unsupported, stop compute-cell; one that empties it
#     forever at compute-gap=0 reaches the time limit (its clock does not wrap).
#@ tier=quick budget=15 slots=5
. "$(dirname "$0")/lib.inc"
o=$RUNS/03-inert
mkdir -p "$o"
C=$G/compute
N=100000
native() { # [-s N] WANT PROG ARGS...: natively, exit 0 (or N) and the last line of output matches WANT
    may=0; if [ "$1" = -s ]; then may=$2; shift 2; fi
    want=$1; shift
    st=0; timeout 20 "$@" >"$o/native.out" 2>&1 || st=$?
    out=$(tail -1 "$o/native.out")
    [ "$st" = 0 ] || [ "$st" = "$may" ] || die "a. $*: natively: exit $st: $out"
    grep -q "$want" <<<"$out" || die "a. $*: natively printed $out"
}
native -s 1 '^balance=-\?[0-9]* withdrawn=[0-9]* \(ok\|DOUBLE-SPEND\)$' "$C/races" b  # its race may show natively
native -s 1 'LOST-UPDATE\|ok$' "$C/pool"  # its race, when it shows natively, exits 1
native '^done$' "$C/spinpoints" count
native 'counter=4000$' "$C/spinwait" own-spin
native '^total=230000$' "$C/cellpoke" scribble
native "^loop $N sum=" "$C/loop" "$N"
echo "a. the compute guests run natively with their normal output"

prun "$o/stock" 1 --config "$("$PATINA_CFG" preempt=traps)" -- /guest/compute/loop-stock "$N" &
prun "$o/loop" 1 --fault compute-gap=0 -- /guest/compute/loop "$N" &
prun "$o/poke-1" 1 -- /guest/compute/cellpoke scribble &
prun "$o/poke-2" 1 -- /guest/compute/cellpoke scribble &
prun "$o/unmap" 1 -- /guest/compute/cellpoke unmap &
prun "$o/drain" 1 --fault compute-gap=0 --config "$("$PATINA_CFG" time-limit=10)" --timeout 10 -- /guest/compute/cellpoke drain &
wait
elapsed() { sed -n 's/.*elapsed_ns=//p' "$1/inc-0/stdout"; }
[ "$(field "$o/stock/result.json" outcome)" = ok ] || die "b. stock loop: $(res "$o/stock")"
[ "$(field "$o/stock/result.json" compute)" = - ] || die "b. a stock run has compute: $(field "$o/stock/result.json" compute)"
"$PATINA" log dump "$o/stock/inc-0/boundary.log" >"$o/stock.dump"
! grep -q 'patina_sdk\|compute' "$o/stock.dump" || die "b. a stock run's log: $(grep -m1 'patina_sdk\|compute' "$o/stock.dump")"
t=$(elapsed "$o/stock")
[ "$t" -lt "$N" ] || die "b. the stock loop of $N iterations took $t virtual ns"
echo "b. stock: no compute key, no SDK call or compute record; loop of $N iterations: $t virtual ns"

[ "$(field "$o/loop/result.json" outcome)" = ok ] || die "c. rebuilt loop: $(res "$o/loop")"
t=$(elapsed "$o/loop")
[ "$t" -ge "$N" ] || die "c. the rebuilt loop of $N iterations took $t virtual ns"
[ "$(field "$o/loop/result.json" compute.switches)" = 0 ] || die "c. switches at compute-gap=0"
echo "c. rebuilt, compute-gap=0: loop of $N iterations: $t virtual ns, $(field "$o/loop/result.json" compute.events) events in the run, no switch"

for r in poke-1 poke-2; do
    [ "$(field "$o/$r/result.json" outcome)" = ok ] || die "d. cellpoke scribble: $(res "$o/$r")"
done
lhs=$(field "$o/poke-1/result.json" digest); rhs=$(field "$o/poke-2/result.json" digest)
[ "$lhs" = "$rhs" ] ||
    die "d. cellpoke scribble: two runs of seed 1 differ"
[ "$(field "$o/unmap/result.json" outcome)/$(field "$o/unmap/result.json" stop)" = unsupported/compute-cell ] ||
    die "d. cellpoke unmap: $(res "$o/unmap")"
[ "$(field "$o/drain/result.json" outcome)" = liveness ] || die "d. cellpoke drain at compute-gap=0: $(res "$o/drain")"
echo "d. scribbles on the cell: one digest twice ($(field "$o/poke-1/result.json" compute.switches) switches); unmapping it: $(res "$o/unmap" | cut -c1-80); emptying it forever: $(res "$o/drain" | cut -c1-60)"
