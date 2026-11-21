# 5. Nodes: a node's processes killed and started again (tests/guests/nodes/kill.py). The
# driver kills node b with `node kill b` and starts it with `node start b`, 50 times
# (10 in the quick tier):
# each kill ends both of b's connections (its first process's and its child's), a connect to
# either port is refused while b is down, a kill of a node that is down and a start of one that
# is up are refused, and each restart finds the work tree the last one left and its own
# PATINA_INCARNATION; result.json, the events and node/b/inc-K/ show every incarnation. The
# same under verify. A node's own end: an exit outside `ok-exit` ends the run `failure`
# naming the node, a signal `crash`; an exit within it stops the node, and `restart = "always"`
# starts it again up to `max-incarnations`; `count` makes that many nodes of one table.
#@ tier=quick budget=60 slots=2
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-kill; mkdir -p "$o"
rm -f "$o/b.toml"; conf "$o/b.toml" b python3 /guest/kill.py b

k=50; [ "${CHECK_TIER:-}" != quick ] || k=10
run_ok "$o/kill" 1 --config "$o/b.toml" -- python3 /guest/kill.py driver $k
sed 's/^/    /' "$o/kill/inc-0/stdout"
[ "$(field "$o/kill/result.json" nodes.list.1.incarnations)" = $((k + 1)) ] || die "b: $(field "$o/kill/result.json" nodes.list.1)"
hows=$(jq -r '[.nodes.list[1].downs[].how] | unique | join(" ")' "$o/kill/result.json")
[ "$hows" = "killed by script" ] || die "b's downs: $hows"
n=$("$PATINA" log events "$o/kill" --types node | grep -c '"event":"kill","name":"b".*"by":"script"')
[ "$n" = $k ] || die "kill events of b: $n"
n=$("$PATINA" log events "$o/kill" --types node | grep -c '"event":"start","name":"b".*"incarnation"')
[ "$n" = $k ] || die "restart events of b: $n"
for i in 0 $((k - 1)) $k; do
    grep -q "^b: start $((i + 1)), incarnation $i\$" "$o/kill/node/b/inc-$i/stdout" \
        || die "node/b/inc-$i/stdout: $(cat "$o/kill/node/b/inc-$i/stdout")"
done
echo "b: $((k + 1)) incarnations, one directory each, $(field "$o/kill/result.json" faults.injected) faults injected"
verify_ok "$o/verify" 2 3 --config "$o/b.toml" -- python3 /guest/kill.py driver 10

# A node's own end.
printf '[node.bad]\ncmd = ["sh", "-c", "sleep 1; exit 3"]\n' >"$o/bad.toml"
c=$(run "$o/bad" 1 --config "$o/bad.toml" -- sleep 10)
[ "$c" = failure ] && [ "$(field "$o/bad/result.json" node_end.node)" = bad ] && [ "$(field "$o/bad/result.json" node_end.exit)" = 3 ] \
    || die "an exit outside ok-exit: $c, $(field "$o/bad/result.json" message)"
printf '[node.seg]\ncmd = ["sh", "-c", "sleep 1; kill -SEGV $$"]\n' >"$o/seg.toml"
c=$(run "$o/seg" 1 --config "$o/seg.toml" -- sleep 10)
[ "$c" = crash ] && [ "$(field "$o/seg/result.json" node_end.node)" = seg ] && [ "$(field "$o/seg/result.json" node_end.signal)" = 11 ] \
    || die "a signal: $c, $(field "$o/seg/result.json" message)"
printf '[node.w]\ncmd = ["sh", "-c", "echo inc=${PATINA_INCARNATION:-0}; sleep 1; exit 3"]\nok-exit = 3\nrestart = "always"\nmax-incarnations = 3\ncount = 2\n' >"$o/w.toml" # lint-allow: sleep — the node's command, in virtual time
run_ok "$o/w" 1 --config "$o/w.toml" --fault down-ms=100..500 -- sleep 10
for w in w1 w2; do
    [ "$(cat "$o/w/node/$w"/inc-*/stdout | tr '\n' ' ')" = "inc=0 inc=1 inc=2 " ] || die "$w: $(cat "$o/w/node/$w"/inc-*/stdout)"
done
echo "outcomes: an exit outside ok-exit failure, a signal crash, both naming the node; ok-exit with restart=always: 3 incarnations of w1 and w2"
