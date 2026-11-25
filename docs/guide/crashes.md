# Crashes: crash points and what a crash leaves on disk

`--faults crash` crashes the machine at a point the seed chooses and starts the program again
with the same arguments, on what had reached the disk: data never synced may be gone, renames and
creations may be undone. `--faults kill` kills the processes and keeps everything they wrote, as
when a program dies but the machine does not. The program must recover on start: read its state
from `/work`, check it, carry on. `PATINA_BOOT=K` is set at boot K: 1 at the first, 2 after the
first crash.

The one crash-modelled disk is main's disk, `/work` (`--disk DIR` fills it, `--disk
DIR:/var/lib/app` puts it where the program expects its data). `/tmp` and other writable places
start empty again after a restart.

## The check after a crash

The oracle compares what the program promised before the crash with what it recovered. With the
SDK, an `always` in recovery; without it, a check over `boot-K/stdout` (what boot K
printed, its acknowledgements) and `boot-K/post-crash/` (the files the crash left, which the next
start recovers from). `examples/kvlog-c` appends records and prints `ack I` once record I is
written, without an fsync; `examples/checks/acked-kept` compares the last acknowledgement with
what the crash left, and does not judge a run without a crash:

<!-- transcript kvlog-sweep
dir: /tmp/kvlog
exit: 0 1
-->
```text
$ cc -o kvlog examples/kvlog-c/kvlog.c
$ patina sweep --seeds 1..30 --fault crash-permille=10 --check examples/checks/acked-kept -- ./kvlog
new: violation check: acked-record-lost: acknowledged N, N stored after the crash   (seed 5: patina replay /tmp/kvlog/patina-out/sweep/seed-5)
sweep: replaying the first seed of 1 finding
sweep: 301.3 KiB kept in /tmp/kvlog/patina-out/sweep
patina sweep: 30 runs, 7 findings in 1 group, 23 ok   (0.8s, 8 jobs)
outcomes: ok 23, violation 7
check: judged 9 of 30 runs: 2 passed, 7 failed; 21 not judged (no crash in this run 21)

violation check: acked-record-lost: acknowledged N, N stored after the crash
  7 of 30 runs   first: seed 5   replayed: identical
  example: acked-record-lost: acknowledged 7, 6 stored after the crash
  faults in every failing run: crash      in none: -
  rerun:  patina run --seed 5 --fault crash-permille=10 --check examples/checks/acked-kept -- /tmp/kvlog/kvlog
  replay: patina replay /tmp/kvlog/patina-out/sweep/seed-5
  explain: patina inspect story /tmp/kvlog/patina-out/sweep/seed-5
```

`./kvlog fixed`, which syncs each record before acknowledging it, is clean under the same sweep.
A promise about "the next start" also holds without a crash (a save that failed halfway, then a
restart): start the program twice in one run, `-- /bin/sh -c './prog; ./prog'`.

## Crash points

A crash falls at a crash point: after each change to `/work` and before each sync, so one
`fsync` holds two. The class crashes at each point with chance `crash-permille` (default 3, so
most runs crash early: a lower rate reaches later points). `--fault crash-at=N` crashes at
exactly the N-th point of the first run (`A..B`: each seed picks one in the range), and a run
crashed at N is the same as the run without the crash up to N. `crashes[].point` in
`result.json`, and `point=` in the `last injected:` lines, say where a crash fell.

A crash that must land in a narrow window (between a write and its fsync) is found in few seeds.
`--crash-points` runs each seed once to count its points, then once per point with the crash
forced there; `--crash-points=N` takes a sample of N per seed, spread over the kinds of
operation, and the same command with a larger N runs only the new ones:

<!-- transcript crash-points
dir: /tmp/acklog
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

Use it first for a crash window; keep plain crash sweeps for bugs that need variety across seeds
(fault plans, a failed fsync at a chosen call). Seeds differ widely in their count of points:
give large ones `--crash-points=N` or `--budget`. Points count only while the faults act: a
setup that should not be crashed finishes before a `ready` probe on main passes (`patina guide
faults`).

## What survives a machine crash

The file system model decides, from the seed, what the crash keeps of what was not synced:

- **`ext4-ordered`** (the default): ext4 with its defaults (`data=ordered`, delayed allocation, a
  journal commit every 5 s). Names, sizes and attributes reach the disk at a commit: an `fsync`
  of a file or directory, a `sync`, every 5 virtual seconds, and one seed-chosen moment. Commits
  are in order, so creations, renames and unlinks survive in the order they were made. New data
  reaches the disk with its file's size, at its `fsync`, at `sync` or at the commit, except that
  an append inside the file's last 4 KiB block can keep the larger size with the new bytes
  reading as zeros. A rewrite of a block already on disk survives old or new, block by block.
  Replacing a file by `rename` over it, or after truncating it to zero, writes the new data
  first.
- **`posix-strict`** (`--fault fs-model=posix-strict`): only what POSIX promises: a file's data
  after its own `fsync` or a `sync`, a name after an `fsync` of its directory. Every other change
  is kept or dropped on its own draw, in any consistent combination. No real file system
  reorders this freely: a finding only `posix-strict` gives is a program relying on more than
  POSIX promises.

What a restart finds:

| | after `kill` | after `crash` |
|---|---|---|
| `/work` | as it was | what the model kept |
| `/tmp`, other writable places | empty | empty |
| process IDs | the same numbers again, from the first | the same |
| the clock | 1 to 61 s later (`down-ms`) | the same |

Process IDs repeat on purpose: a lock file naming a dead holder now names a live process. A run
has at most 4 boots (`max-boots`), the last never crashed. The other fault
classes stay on after a restart, so recovery meets them too; `patina minimize` shows whether the
crash alone fails the run.

## Reading a crash

`patina inspect story RUNDIR` shows the writes, fsyncs and the crash in order, and at the crash which
files had writes not followed by an fsync. `patina inspect ops RUNDIR/boot-1` lists every change to
`/work`; `patina inspect tree --post-crash RUNDIR/boot-1 DIR` writes the tree the crash left. With
several machines each machine's disk crashes on its own (`patina guide machines`).
