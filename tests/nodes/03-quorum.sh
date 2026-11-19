# 3. Nodes: a three-node replicated store with failover (tests/guests/nodes/q3.py: a primary,
# two backups, quorum writes, leased reads, view changes that fence the old primary) under the
# seed's partitions and the net preset. Correct: ok on every seed of a sweep, with failovers in
# some (a view above 0), partitions drawn and acting on traffic; identical under verify. The
# planted bug of reads without the lease (`nolease`: a stale read from the old primary after a
# one-way or isolating cut) is found in most seeds of a sweep, and its first failing run replays
# identically. The other planted bugs are 04-quorum-bugs's.
#@ tier=quick budget=90 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/03-quorum; mkdir -p "$o"

out=$(q3_sweep "$o" ok all)
[ "$out" = '{"ok": 8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
failover=$(cat "$o"/ok/seed-*/inc-0/stdout | awk '/views up to [1-9]/ { n++ } END { print n + 0 }')
[ "$failover" -ge 2 ] || die "correct: a failover in only $failover of 8 runs"
acted=$(field "$o/ok/report.json" nodes.partitions.acted)
[ "$acted" -ge 8 ] || die "correct: partitions acted on traffic $acted times over 8 runs"
echo "correct: ok on seeds 1-8, a failover in $failover, partitions $(field "$o/ok/report.json" nodes.partitions)"
s=$(grep -l 'views up to [1-9]' "$o"/ok/seed-*/inc-0/stdout | sed -n '1s,.*/seed-\([0-9]*\)/.*,\1,p')
verify_ok "$o/verify" "$s" 3 --config "$o/ok.toml" $Q3_FAULTS -- python3 /guest/q3.py driver 60

q3_bug "$o" nolease
