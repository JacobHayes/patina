# 1. Quorum: a three-machine replicated store with failover (tests/guests/machines/q3.py: a primary,
# two backups, quorum writes, leased reads, view changes that fence the old primary) under the
# seed's partitions and the net class. Correct: ok on every seed of a sweep, partitions drawn
# and acting on traffic, and a failover (a view above 0; searched past the sweep's seeds if
# none of them had one), identical under verify. The planted bug of reads without the lease
# (`nolease`: a stale read from the old primary after a one-way or isolating cut) is found by a
# search of seeds, and its first failing run replays identically. The other planted bugs are
# 02-quorum-bugs's.
#@ tier=area budget=90 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-quorum; mkdir -p "$o"

out=$(q3_sweep "$o" ok all)
[ "$out" = '{"ok":8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
acted=$(field "$o/ok/report.json" machines.partitions.acted)
[ "$acted" -ge 1 ] || die "correct: no partition acted on traffic in 8 runs"
# A failover: the first seed of the sweep with one, or later seeds one at a time, each ok.
s=$(grep -l 'views up to [1-9]' "$o"/ok/seed-*/boot-1/stdout | sed -n '1s,.*/seed-\([0-9]*\)/.*,\1,p')
k=9
while [ -z "$s" ] && [ $k -le $FIND_SEEDS ]; do
    run_ok "$o/ok-$k" $k --config "$o/ok.toml" $Q3_FAULTS -- python3 /guest/q3.py main 60
    if grep -q 'views up to [1-9]' "$o/ok-$k/boot-1/stdout"; then s=$k; fi
    k=$((k + 1))
done
[ -n "$s" ] || die "correct: no failover in seeds 1-$FIND_SEEDS (the scenario never arose)"
echo "correct: ok on seeds 1-8, the first failover at seed $s, partitions $(field "$o/ok/report.json" machines.partitions)"
verify_ok "$o/verify" "$s" 3 --config "$o/ok.toml" $Q3_FAULTS -- python3 /guest/q3.py main 60

q3_bug "$o" nolease
