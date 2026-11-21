# Nodes: several machines in one run

A run can hold several machines, called nodes. The command after `--` is the **driver**: it is
never faulted, and the run ends with its exit status. Each `[node.NAME]` table in
`patina.toml`, or `--node NAME='CMD ARGS'`, adds a node whose program starts with the run, before
the driver:

<!-- transcript nodes-kv
dir: /tmp/nodes
setup: mkdir g && cp "$GUESTS/kv.py" "$GUESTS/patina.py" g/
setup: printf '[node.primary]\ncmd = ["python3", "/guest/kv.py", "primary"]\n\n[node.backup]\ncmd = ["python3", "/guest/kv.py", "backup"]\n' >patina.toml
-->
```text
$ cat patina.toml
[node.primary]
cmd = ["python3", "/guest/kv.py", "primary"]

[node.backup]
cmd = ["python3", "/guest/kv.py", "backup"]
$ patina run --mount g:/guest:copy -- python3 /guest/kv.py driver
ok (exit): the program exited 0
guest: exit 0
nodes: primary 10.0.0.2 running, backup 10.0.0.3 running; net: 1 cuts, 1 heals, 1 held, none cut at the end
run directory: /tmp/nodes/patina-out/run-0
replay: patina replay /tmp/nodes/patina-out/run-0
```

`kv.py` (in `tests/guests/nodes`) is a store whose primary sends each write to the backup; the
driver writes, cuts the link between them, sees the next write wait, heals it, and checks both
agree. To test a distributed system, put the system under test on nodes and make the driver the
harness: wait for the system, mark `setup-complete`, drive the workload, mark `faults-done`,
check (`patina guide faults`).

**What a node has of its own:** a work tree (its disk), `/tmp`, its hostname (its name), a port
space, a loopback, and the address `10.0.0.K` (the driver `10.0.0.1`, the first node
`10.0.0.2`); `/etc/hosts` names every node. `/usr`, the mounts and the program's directory are
shared and read-only. A listener on `0.0.0.0` is reachable from every node, one on `127.0.0.1`
only from its own. A node's output is in `RUNDIR/node/NAME/inc-K/`. Up to 15 nodes;
`count = N` in a table makes N of them. The node keys are in `patina guide config`.

## The driver's control: `patina ctl`

The driver acts on the network and the nodes with control calls: `patina ctl WORDS` in a script
(`patina` is on the `PATH` of a run with nodes), or the SDK's `control("WORDS")`.

| Words | |
|---|---|
| `net cut A B`, `net cut --from A --to B` | cut both directions between node sets A and B, or one |
| `net heal A B`, `net heal` | heal those links, or every cut |
| `node crash NAME` | crash the node's machine: unsynced data may be lost, its peers hear nothing |
| `node kill NAME` | kill every process of the node; its disk is kept |
| `node start NAME` | start a node that is down |
| `node pause NAME`, `node resume NAME` | freeze the node and let it run again |
| `clock step NAME +90s` | move the node's realtime clock |
| `mark LABEL` | as the SDK's `mark`: `setup-complete`, `faults-done`, or a promise |

A set is node names joined by commas (`driver` included), or `rest`. A cut holds TCP data, as a
pulled cable does, until a heal or the sender's timeout; datagrams across it are lost.

## The seed's faults on nodes

- `--faults net`: delays, resets and the rest on the links between nodes (not the driver's:
  `--fault net-links=driver` adds them).
- `--faults partition`: cuts between groups of nodes for a while (two nodes or more).
- `--faults pause`: a node frozen for a while; its peers see a live machine that does not answer.
- `--faults clock`: each boot of a node draws a realtime clock offset.
- `--faults crash` or `--faults kill`: machine crashes or process kills at drawn times, each
  followed by a restart (`--fault crash-gap-ms=2000..10000` for frequent ones in a short run).
- `--faults disk`, `mem`, `buggify`: each node's own.

`@NODE,...` scopes a class or key to nodes: `--faults crash@db`, `--fault
fsync-error-permille=5@a,driver`. `[node.NAME] faults = false` keeps a node out of unscoped
faults. A group's `nodes:` line says which nodes were down or partitioned in its failing runs.

<!-- transcript nodes-sweep
dir: /tmp/q3
setup: mkdir g && cp "$GUESTS/q3.py" "$GUESTS/patina.py" g/
setup: for n in n1 n2 n3; do printf '[node.%s]\ncmd = ["python3", "/guest/q3.py", "%s", "nosync"]\n\n' $n $n; done >patina.toml
exit: 1
release-only: a sweep of eight runs of a three-node cluster
-->
```sh
patina sweep --seeds 1..8 --mount g:/guest --faults net,partition,pause,clock,crash --fault crash-gap-ms=2000..10000 -- python3 /guest/q3.py driver 30
```

`q3.py` is a store on three nodes; with `nosync` a node acknowledges a write before it is on
disk, and a write the cluster acknowledged is lost when the nodes that had it crash. Without
`nosync` the same sweep is clean.

## Every crash point of every node

Each node counts crash points on its own disk. `patina sweep --crash-points` (with `--faults
crash@a,b` to name nodes) crashes one node's machine at each of its points in turn; `[sweep]
crash-pairs = K` also crashes a second node at each of its next K points after every first
crash. Give large runs `--crash-points=N`. `--fault crash-at=N@NODE` crashes one node at one
point.

<!-- transcript nodes-points
release-only: a sweep of a seed's 30 crash points
dir: /tmp/ack2
setup: mkdir g && cp "$GUESTS/ack2.py" "$GUESTS/patina.py" g/
setup: printf '[node.a]\ncmd = ["python3", "/guest/ack2.py", "a"]\n[node.b]\ncmd = ["python3", "/guest/ack2.py", "b", "early"]\n' >patina.toml
exit: 1
-->
```text
$ patina sweep --seeds 1 --crash-points -j 4 --mount g:/guest:copy -- python3 /guest/ack2.py driver 3
...
crash points: 30 of 30 tried (a 15 of 15, b 15 of 15)
...
```

`ack2.py` forwards each put from node a to b and acknowledges it once b answers; with `early`, b
answers before its `fsync`, and a crash of b loses an acknowledged put.

## In the logs

`result.json`'s `nodes` lists each node with its address, incarnations and downs (how, when, for
how long, what its disk lost), its pauses and clock, and the partitions. `patina log events`
names each thread's node and adds `node` and `net` events; `patina explain` tells the story by
node. Seeds, `replay` and `verify` work as on one machine: one scheduler, one clock, one log.
