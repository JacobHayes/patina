# 6. Nodes: the three-node store of 03-quorum (tests/guests/nodes/q3.py, each node keeping its
# view and log in its work tree) under the seed's node kills (`--crash process`), each node
# restarted after a drawn down time. Correct: ok on every seed of a sweep, with kills and
# restarts in every run; identical under verify. Planted bug: a node that forgets its log when
# it restarts (`amnesia`) loses acknowledged writes, found in most seeds; its first failing run
# replays identically.
#@ tier=quick budget=90 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-quorum-kills; mkdir -p "$o"
Q3_FAULTS="--crash process --fault crash-gap-ms=2000..10000 --fault down-ms=500..3000"
Q3_SECONDS=40

out=$(q3_sweep "$o" ok all)
[ "$out" = '{"ok": 8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
# Runs in which every node was killed and restarted, and the kills over the sweep.
set -- $(python3 -I -c 'import json,sys
n=k=0
for f in sys.argv[1:]:
    r=json.load(open(f))
    n+=min(v.get("incarnations", 1) - 1 for v in r["nodes"]["list"][1:]) > 0
    k+=r["faults"]["counts"]["crash"]["injected"]
print(n, k)' "$o"/ok/seed-*/result.json)
[ "$1" -ge 6 ] || die "correct: every node restarted in only $1 of 8 runs"
echo "correct: ok on seeds 1-8, every node killed and restarted in $1, $2 kills"
verify_ok "$o/verify" 1 3 --config "$o/ok.toml" $Q3_FAULTS -- python3 /guest/q3.py driver $Q3_SECONDS

q3_bug "$o" amnesia
