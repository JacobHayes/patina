# 2. Nodes: a primary/backup key-value store (tests/guests/nodes/kv.py) with synchronous
# replication on two nodes. The driver writes and reads back from the backup, cuts the link
# between them with `patina.control`, sees the next write wait and the backup fall behind, heals,
# and checks that the write completes and both sides converge. Correct: ok on seeds 1-4, each
# with its own schedule (distinct digests), and identical under verify. The cut held the
# replication: `nodes.net.held` counts it. Outside the quick tier, the planted bug (the backup
# acknowledges before it applies): a stale read in most of seeds 1-8, and the first replays
# identically.
#@ tier=quick budget=30 slots=2
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-kv; mkdir -p "$o"
for v in ok bug; do
    b=""; [ "$v" = ok ] || b=bug
    conf "$o/$v.toml" primary python3 /guest/kv.py primary $b
    conf "$o/$v.toml" backup python3 /guest/kv.py backup $b
done
for s in 1 2 3 4; do
    run_ok "$o/ok-$s" "$s" --config "$o/ok.toml" -- python3 /guest/kv.py driver
    [ "$(field "$o/ok-$s/result.json" nodes.net.held)" -ge 1 ] || die "seed $s: the cut held nothing"
done
sed 's/^/    /' "$o/ok-1/inc-0/stdout"
n=$(for s in 1 2 3 4; do field "$o/ok-$s/result.json" digest; done | sort -u | wc -l)
[ "$n" = 4 ] || die "seeds 1-4: $n distinct digests"
echo "correct: ok on seeds 1-4, $n distinct schedules"
verify_ok "$o/verify" 1 3 --config "$o/ok.toml" -- python3 /guest/kv.py driver
[ "${CHECK_TIER:-}" != quick ] || exit 0

stale=0; first=""
for s in 1 2 3 4 5 6 7 8; do
    c=$(run "$o/bug-$s" "$s" --config "$o/bug.toml" -- python3 /guest/kv.py driver)
    if [ "$c" = failure ] && grep -q '^FAIL: stale read' "$o/bug-$s/inc-0/stdout"; then
        stale=$((stale + 1)); first=${first:-$s}
    fi
done
[ "$stale" -gt 4 ] || die "planted bug: a stale read in only $stale of seeds 1-8"
echo "planted bug: a stale read in $stale of seeds 1-8; seed $first: $(cat "$o/bug-$first/inc-0/stdout" | tail -1)"
st=0; timeout 120 "$PATINA" replay "$o/bug-$first" >"$o/replay.txt" 2>&1 || st=$?
lhs=$(field "$o/bug-$first/replay/result.json" digest); rhs=$(field "$o/bug-$first/result.json" digest)
[ "$lhs" = "$rhs" ] || die "seed $first: the replay differs (exit $st: $(tail -2 "$o/replay.txt"))"
echo "seed $first replayed identically"
