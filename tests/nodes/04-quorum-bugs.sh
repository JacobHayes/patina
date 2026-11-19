# 4. Nodes: the three-node store of 03-quorum with its other planted bugs, each found in most
# seeds of a sweep, its first failing run replaying identically: acknowledging before a quorum
# (`early`) and an isolated old primary that acknowledges on its own (`nofence`), both a split
# brain.
#@ tier=quick budget=90 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-quorum-bugs; mkdir -p "$o"
q3_bug "$o" early
q3_bug "$o" nofence
