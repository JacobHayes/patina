# What to vary

Every setting below is drawn from the seed, so any finding replays from its `rerun:` line.
Add one kind at a time, starting from the bug you suspect; a run that meets every fault at
once fails in ways that say little. `patina run --help` lists every fault key of your build.

## The schedule (always on)

Each seed is another interleaving: threads switch at every system call and spin-wait, so races
on locks, files, pipes, sockets and channels need no flag. `--cpus N` (default 4) changes the
CPU count the program sees, and so its thread pools.

A race on plain memory with no system call between the accesses (a counter updated without
its lock, check-then-act on an atomic) needs switch points inside the computation:

- `--preempt points`: stock code and every library it loads get points at backward branches,
  calls, indirect jumps and atomics; add `--fault compute-gap=2..64` for a short test whose
  threads run few events. JIT output gets none.
- A rebuild with compute points (clang coverage flags plus `sdk/c/patina_compute.c`; Rust,
  Go: see the guide's "Deeper search"; Python: `python3 -m patina` with `sdk/python` on
  `PYTHONPATH`) puts a point at every load and store: the densest, for code you build.

`patina run` prints `load-time points:` or `compute points:` when they took; no line means none
did. A seed found with points does not replay without them.

## Disk: `--faults disk`

Errors, short reads and writes, failed fsyncs and delays on files under `/work`, pipes and unix
sockets, each an error Linux can return there. Pair it with `--ok-exit` and a check of the
output ([oracles.md](oracles.md)): most disk-fault findings exit 0 with wrong data or exit
cleanly. One key alone: `--fault fs-short-permille=20`. `--fault path-swap-permille=300`
changes a path between a check and its use: only for a program that must withstand another
writer in its directory.

## Crashes: `--crash machine`, `--crash process`

`machine` crashes the whole program at a seed-chosen crash point (after each change to
`/work`, before each sync) and starts it again with the same arguments on what had reached the
disk; `process` kills it but keeps what it wrote. The program must recover on start: read its
state from `/work`, check it, carry on (`PATINA_INCARNATION=K` is set after the K-th restart).
Up to 3 restarts per run. The oracle compares what the program promised before the crash with
what it recovered: an `always` in recovery, or a check over `inc-K/stdout` and
`inc-K/post-crash/`.

A crash that must land in a narrow window (between a write and its fsync) is found in few
seeds. `--branch` runs each seed once to count its crash points, then once per point:

<!-- transcript branch
dir: /tmp/crash
setup: cp "$GUESTS/examples/acklog" .
exit: 1
-->
```text
$ patina sweep --seeds 1..2 --branch --branch-max 40 --crash machine -- ./acklog
sweep: 2 seeds, 328 crash points, a sample of 80 (--branch-max)
...
crash points: 80 of 328 tried
  seed 1: 40 of 164   seed 2: 40 of 164
...
```

`--branch-max N` samples N points per seed; the same command with a larger N runs only the new
ones. `--crash machine-at:N` (or `A..B`) crashes at a chosen point; `patina explain` of a run
shows which operation each crash point followed.

A promise about "the next start" also holds without a crash (a save that failed halfway, then a
restart). Start the program twice in one run: `--mount DIR:/app -- /bin/sh -c '/app/prog;
/app/prog'` (only the program named after `--` has its own directory visible).

## Network: `--faults net`

Delays, chunked deliveries, resets, refused connects, and for UDP drops, duplicates and
reordering, on loopback and between nodes. A reset is drawn on each piece of data sent, so a
retrying client meets one; one key alone: `--fault net-reset-permille=50`.
`--fault net-blackout=0..60000+1000..10000` holds traffic for a while, as across a cut cable.
`--faults all` is disk and net together, with memory errors: only after each alone.

## Several machines: nodes

Each `[node.NAME]` table in `patina.toml` (or `--node NAME='CMD ARGS'`) is a machine with its
own disk, address (`10.0.0.2`, ...), hostname and clock; names resolve on every node. The
command after `--` is the driver: never faulted, it runs the test and decides the exit status.
From the driver, `patina ctl net cut a b`, `net heal`, `node kill NAME` (machine crash) or
`node kill NAME --process`, `node start NAME`, `node pause NAME` script a scenario; the seed
does the same with:

- `--faults net`: link faults, and partitions between nodes (`--fault partition-gap-ms=A..B`).
- `--crash machine` or `--crash process`: kills or machine crashes at seed-drawn times
  (`--fault crash-gap-ms=2000..10000` for short runs), each followed by a restart.
- `--faults cluster`: link faults, partitions, pauses, clock skew and machine crashes together.
- `--branch --crash machine`: every crash point of each node; `--branch-pairs K` also crashes a
  second node after each first crash; give large runs a `--branch-max`.

See [recipes.md](recipes.md) for a replicated store.

## If a sweep finds nothing

In order of what helps most: more seeds (a narrow window is one seed in thousands); `--branch`
for crash windows; `--buggify`, or `--fault point:LABEL=1000` to fire one fault point every
time; a lower crash rate (`--crash machine:1`) to reach later points; `--preempt points` for
races with no system call in them. Then say what was tried, and that the oracle is what decides what clean
means.
