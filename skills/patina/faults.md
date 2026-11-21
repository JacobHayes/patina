# What to vary

Every setting below is drawn from the seed, so any finding replays from its `rerun:` line.
Add one kind at a time, starting from the bug you suspect; a run that meets every fault at
once fails in ways that say little. `patina run --fault help` lists every fault key of your build.

## The schedule (always on)

Each seed is another interleaving: threads switch at every system call and spin-wait, and at
load-time points inside computation (the program and every library it loads are rewritten as
they are mapped, with a point at backward branches, calls, indirect jumps and atomics, and some
switches a few instructions past one). So races on locks, files, pipes, sockets and channels,
and on plain memory (a counter updated without its lock, check-then-act on an atomic), need no
flag. `[run] cpus = N` in patina.toml (default 4) changes the CPU count the program sees, and so
its thread pools.

JIT output gets no points. For a race between accesses far from any point, rebuild with compute
points (clang coverage flags plus `sdk/c/patina_compute.c`; Rust, Go: see the guide's "Deeper
search"; Python: `python3 -m patina` with `sdk/python` on `PYTHONPATH`): a point at every load
and store.

`patina run` prints `load-time points:` when code went without points, naming any file left
without a plan and counting JIT or other unpatched executable memory (and `compute points:` for
rebuilt code).

## Disk: `--faults disk`

Errors, short reads and writes, failed fsyncs and delays on files under `/work`, pipes and unix
sockets, each an error Linux can return there. Pair it with `--ok-exit` and a check of the
output ([oracles.md](oracles.md)): most disk-fault findings exit 0 with wrong data or exit
cleanly. One key alone: `--fault fs-short-permille=20`. `--fault path-swap-permille=300`
changes a path between a check and its use: only for a program that must withstand another
writer in its directory.

## Crashes: `--faults crash`, `--faults kill`

`crash` crashes the whole program at a seed-chosen crash point (after each change to
`/work`, before each sync) and starts it again with the same arguments on what had reached the
disk; `kill` kills it but keeps what it wrote. The program must recover on start: read its
state from `/work`, check it, carry on (`PATINA_INCARNATION=K` is set after the K-th restart).
Up to 3 restarts per run. The oracle compares what the program promised before the crash with
what it recovered: an `always` in recovery, or a check over `inc-K/stdout` and
`inc-K/post-crash/`.

A crash that must land in a narrow window (between a write and its fsync) is found in few
seeds. `--crash-points` runs each seed once to count its crash points, then once per point:

<!-- transcript branch
dir: /tmp/crash
setup: cp "$GUESTS/examples/acklog" .
exit: 1
-->
```text
$ patina sweep --seeds 1..2 --crash-points=40 -- ./acklog
sweep: 2 seeds, 328 crash points, a sample of 80 (--crash-points=N)
...
crash points: 80 of 328 tried
  seed 1: 40 of 164   seed 2: 40 of 164
...
```

`--crash-points=N` samples N points per seed; the same command with a larger N runs only the new
ones. `--fault crash-at=N` (or `A..B`) crashes at a chosen point; `patina explain` of a run
shows which operation each crash point followed.

A promise about "the next start" also holds without a crash (a save that failed halfway, then a
restart). Start the program twice in one run: `--mount DIR:/app -- /bin/sh -c '/app/prog;
/app/prog'` (only the program named after `--` has its own directory visible).

## Network: `--faults net`

Delays, chunked deliveries, resets, refused connects, and for UDP drops, duplicates and
reordering, on loopback and between nodes. A reset is drawn once per connection, at a drawn
send, so most connections survive; to reset (nearly) every one: `--fault net-reset-permille=1000`.
`--fault net-blackout=0..60000+1000..10000` holds traffic for a while, as across a cut cable.
Memory errors (`--faults mem`: `ENOMEM`, failed thread creation) are for a program that handles
allocation failure.
`--faults all` is every class that applies except `crash` and `kill` (add them: `--faults all,crash`): only after each alone.

## Several machines: nodes

Each `[node.NAME]` table in `patina.toml` (or `--node NAME='CMD ARGS'`) is a machine with its
own disk, address (`10.0.0.2`, ...), hostname and clock; names resolve on every node. The
command after `--` is the driver: never faulted, it runs the test and decides the exit status.
From the driver, `patina ctl net cut a b`, `net heal`, `node crash NAME` (machine crash) or
`node kill NAME`, `node start NAME`, `node pause NAME` script a scenario; the seed
does the same with:

- `--faults net`: link faults. `--faults partition` cuts links between nodes
  (`--fault partition-gap-ms=A..B`).
- `--faults pause` and `--faults clock`: a node stops for a while; a node's clock is off.
- `--faults crash` or `--faults kill`: machine crashes or kills at seed-drawn times
  (`--fault crash-gap-ms=2000..10000` for short runs), each followed by a restart. Name a node
  to fault only it: `--faults crash@db`.
- `--crash-points`: every crash point of each node; `[sweep] crash-pairs = K` also
  crashes a second node after each first crash; give large runs a `--crash-points=N`.

To test a distributed system, put the system under test on a node and let the driver be the
harness: it waits for the system, marks `setup-complete`, drives the workload, marks
`faults-done`, and checks.

<!-- no-run sweep: needs a database to test, which the repo does not ship -->
```sh
patina sweep --seeds 1..200 --faults all,crash --node sut='./db --listen :7000' -- ./harness
```

<!-- no-run harness: the driver script the sweep above runs -->
```sh
#!/bin/sh
# harness: the driver
until nc -z sut 7000; do sleep 0.1; done
patina ctl mark setup-complete
./workload sut:7000
patina ctl mark faults-done
./verify sut:7000
```

See [recipes.md](recipes.md) for a replicated store.

## If a sweep finds nothing

In order of what helps most: more seeds (a narrow window is one seed in thousands); `--crash-points`
for crash windows; `--faults buggify`, or `--fault buggify:LABEL=1000` to fire one fault point every
time; a lower crash rate (`--fault crash-permille=1`) to reach later points; a rebuild with compute
points for races between plain accesses far from any loop, call or atomic. Then say what was
tried, and that the oracle is what decides what clean means.
