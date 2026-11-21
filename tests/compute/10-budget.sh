# 10. The switch budget (proto::compute::budget) holds load-time points alone, per process.
# The first seed of 1-20 whose default gap is at most 16 events, for examples/stats-c built
# with compute points (`stats-cp`) and stock (`stats`), each run at its default gap and with that gap named
# (`--fault compute-gap`, which no budget holds):
#  a. stats-cp gives the same digest both ways: in a process whose rebuilt code has said hello the
#     points switch at the drawn gap throughout;
#  b. stats takes fewer switches at its default gap than with the gap named: the budget held it.
#@ tier=quick budget=20 slots=4
. "$(dirname "$0")/lib.inc"
d=$RUNS/10-budget # not o: prun sets it
mkdir -p "$d"
seed="" gap=""
for s in $(seq 1 20); do
    prun "$d/cp-$s" "$s" -- /guest/examples/stats-cp
    g=$(field "$d/cp-$s/result.json" compute.gap)
    [ "$g" != - ] || die "stats-cp seed $s: no compute.gap ($(res "$d/cp-$s"))"
    if [ "$g" -le 16 ]; then seed=$s gap=$g; break; fi
done
[ -n "$seed" ] || die "no seed of 1-20 drew a gap of at most 16"
prun "$d/cp-named" "$seed" --fault compute-gap="$gap" -- /guest/examples/stats-cp &
prun "$d/stock" "$seed" -- /guest/examples/stats &
prun "$d/stock-named" "$seed" --fault compute-gap="$gap" -- /guest/examples/stats &
wait
a=$(field "$d/cp-$seed/result.json" digest) b=$(field "$d/cp-named/result.json" digest)
[ "$a" != - ] && [ "$a" = "$b" ] || die "a. stats-cp seed $seed (gap $gap): digest $a at the default, $b with the gap named (switches $(field "$d/cp-$seed/result.json" compute.switches) and $(field "$d/cp-named/result.json" compute.switches))"
echo "a. stats-cp seed $seed (gap $gap): one digest both ways, $(field "$d/cp-named/result.json" compute.switches) switches"
x=$(field "$d/stock/result.json" compute.switches) y=$(field "$d/stock-named/result.json" compute.switches)
[ "$x" -lt "$y" ] || die "b. stats seed $seed (gap $gap): $x switches at the default, $y with the gap named"
echo "b. stats seed $seed: $x switches at the default, $y with the gap named"
