# 4. Quorum: the three-node store of 01-quorum (tests/guests/nodes/q3.py, each node syncing its
# view and log before it answers) under the seed's machine crashes (`--crash machine`) and
# partitions. Correct: ok on every seed of a sweep, every node's machine crashed and restarted
# in some run, the self-check passing in all; identical under verify. Planted bug: nodes that
# answer without syncing (`nosync`) lose an acknowledged write when the machines holding it
# crash before it reached their disks, found by a search of seeds; its first failing run
# replays identically.
#@ tier=area,release budget=90 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-quorum-machine; mkdir -p "$o"
Q3_FAULTS="--crash machine --fault crash-gap-ms=1000..4000 --fault down-ms=200..1000 --faults net --fault partition-gap-ms=1000..6000 --fault partition-ms=1000..6000"
Q3_SECONDS=40
out=$(q3_sweep "$o" ok all)
[ "$out" = '{"ok": 8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
set -- $(python3 -I -c 'import json,sys
n=set(); k=c=0
for f in sys.argv[1:]:
    r=json.load(open(f))
    downs=[[d["how"] for d in v.get("downs", [])] for v in r["nodes"]["list"][1:]]
    n|={i for i, d in enumerate(downs) if "machine crash" in d}
    k+=sum(d.count("machine crash") for d in downs)
    c+=r["self_check"]["verdict"] == "pass"
print(len(n), k, c, len(r["nodes"]["list"]) - 1)' "$o"/ok/seed-*/result.json)
[ "$1" = "$4" ] || die "correct: only $1 of the $4 nodes' machines crashed in 8 runs"
[ "$3" = 8 ] || die "correct: the self-check passed in only $3 of 8 runs"
echo "correct: ok on seeds 1-8, every node's machine crashed, $2 crashes, self-check passed in all"
verify_ok "$o/verify" 1 3 --config "$o/ok.toml" $Q3_FAULTS -- python3 /guest/q3.py driver $Q3_SECONDS
q3_bug "$o" nosync
