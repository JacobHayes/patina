# 10. Nodes: the three-node store of 03-quorum (tests/guests/nodes/q3.py, each node syncing its
# view and log before it answers) under the seed's machine crashes (`--crash machine`) and
# partitions. Correct: ok on every seed of a sweep, every node's machine crashed and restarted
# in most runs; identical under verify. Planted bug: nodes that answer without syncing
# (`nosync`) lose an acknowledged write when the machines holding it crash before it reached
# their disks, found in most seeds; its first failing run replays identically.
#@ tier=quick budget=90 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-quorum-machine; mkdir -p "$o"
Q3_FAULTS="--crash machine --fault crash-gap-ms=1000..4000 --fault down-ms=200..1000 --faults net --fault partition-gap-ms=1000..6000 --fault partition-ms=1000..6000"
Q3_SECONDS=40
out=$(q3_sweep "$o" ok all)
[ "$out" = '{"ok": 8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
set -- $(python3 -I -c 'import json,sys
n=k=c=0
for f in sys.argv[1:]:
    r=json.load(open(f))
    downs=[[d["how"] for d in v.get("downs", [])] for v in r["nodes"]["list"][1:]]
    n+=min(d.count("machine crash") for d in downs) > 0
    k+=sum(d.count("machine crash") for d in downs)
    c+=r["self_check"]["verdict"] == "pass"
print(n, k, c)' "$o"/ok/seed-*/result.json)
[ "$1" -ge 6 ] || die "correct: every node's machine crashed in only $1 of 8 runs"
[ "$3" = 8 ] || die "correct: the self-check passed in only $3 of 8 runs"
echo "correct: ok on seeds 1-8, every node's machine crashed in $1, $2 crashes, self-check passed in all"
verify_ok "$o/verify" 1 3 --config "$o/ok.toml" $Q3_FAULTS -- python3 /guest/q3.py driver $Q3_SECONDS
q3_bug "$o" nosync
