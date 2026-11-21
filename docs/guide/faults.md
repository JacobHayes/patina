# Faults: the classes, the keys, and when faults act

Faults are drawn from the seed like everything else, so every finding replays. Name the kinds of
fault, the classes; each class turns on settings whose values are ranges, and each seed draws a
value in each range, so one sweep covers gentle and harsh settings. Add one class at a time,
starting from the bug you suspect: a run that meets every fault at once fails in ways that say
little.

    --faults CLASS[,CLASS...][@NODE,...]     repeatable; [faults] faults = ["CLASS", ...]
    --fault  KEY=VALUE[@NODE,...]            repeatable; [faults] KEY = VALUE

`patina run --fault help` prints every class with the ranges it turns on, and every key.

| Class | What the seed does |
|---|---|
| `disk` | errors, short reads and writes, failed write-backs and delays on files under `/work`, pipes and unix sockets: each an error Linux can return for that call |
| `net` | delays, split deliveries, connection resets and refused connects; for datagrams, drops, duplicates and reordering |
| `mem` | `ENOMEM` from memory requests, `EAGAIN` from thread creation |
| `buggify` | the program's own fault points fire (`patina guide sdk`) |
| `crash` | the machine crashes and the program restarts on what reached the disk (`patina guide crashes`) |
| `kill` | the program's processes are killed and restarted; the disk keeps everything |
| `partition` | links between nodes are cut for a while (`patina guide nodes`) |
| `pause` | a node stops for a while, its sockets open |
| `clock` | a node's realtime clock is off by a drawn amount |
| `all` | every class that applies to the run, but `crash` and `kill`: name those, `--faults all,crash` |

## The rules

1. **A class turns on its settings; a key sets one.** `--fault KEY=VALUE` replaces its class's
   value, or turns on that one thing alone: `--fault fs-short-permille=20`, `--fault
   net-reset-permille=1000` (every connection reset at a drawn send), `--fault crash-at=8`. Any
   number may be a range `A..B`, drawn per seed.
2. **Crashes are named.** Surviving a restart is a promise you assert about the program, so `all`
   leaves out `crash` and `kill`.
3. **Every fault asked for must have had something to act on.** A fault of a class that acted
   on something else is listed on a `faults: not applicable` line (datagram faults for a TCP
   program). A class that acted on nothing in any run, or a key you named yourself that never
   applied, makes the sweep `vacuous`: you asked for it. `--faults disk` acts on files under
   `/work`, pipes and unix sockets: a `--stdin FILE` is neither, so feed input through a pipe
   (`-- sh -c 'cat input | ./prog'`) or a file in `/work` to put its reads under faults. Keep a
   harness script out of `/work` (`--mount` it): there its own reads meet the faults too.
4. **Nodes.** With several machines, a class or key without `@` acts on every node but the
   driver; `@a,b` names nodes (`patina guide nodes`). `partition`, `pause` and `clock` exist only
   with nodes.

<!-- transcript not-applicable
dir: /tmp/sockets
setup: cp "$GUESTS/sockets" .
-->
```text
$ patina sweep --seeds 1..20 --faults net --out patina-out/tcp -- ./sockets chunk correct
...
faults: not applicable (a class's, nothing to act on in any run): net-drop, net-dup, net-reorder
```

## When faults act: setup-complete and faults-done

Most programs have a setup that is not under test (create the schema, start the cluster, load
the fixture) and final checks that should see a quiet system (read everything back, compare
replicas). Mark both ends, with the SDK (`setup_complete()`, `faults_done()`; `patina guide
sdk`) or from a script (`patina ctl mark setup-complete`, `patina ctl mark faults-done`).

Faults act from the start of the run, or from `setup-complete` if the program makes that mark,
and stop at `faults-done`: after it nothing more is injected, a partition heals, a paused node
resumes, and no node is crashed again. A program that marks `setup-complete` runs with faults
held until the mark; Patina finds that out on its first run and remembers it. Crash points count
only between the two marks.

**Put the system under test on a node; the driver is the harness.** The command after `--`
waits for the system, marks the setup done, drives the workload, marks the faults done, and
checks:

<!-- no-run node-harness: needs a database to test, which the repository does not ship -->
```sh
patina sweep --seeds 1..200 --faults all,crash --node db='./db --listen :7000' -- ./harness
```

<!-- no-run harness-script: the driver the sweep above runs -->
```sh
#!/bin/sh
# harness: the driver
until nc -z db 7000; do sleep 0.1; done
patina ctl mark setup-complete
./workload db:7000
patina ctl mark faults-done
./verify db:7000
```

A run with one node costs about what a run without nodes does.

## What the keys do

- **Disk.** An injected error is one Linux returns for that call on that object. A failed
  write-back (`fsync-error-permille`) is reported as Linux reports it, once to each open file
  description, and the data it held is lost to a later machine crash even if a later `fsync`
  succeeds. `fs-error-at=CLASS:N`, `fsync-error-at=N` fail one chosen call.
- **Network.** `net-chunk-max` splits the head of each TCP delivery, so every message meets a
  short read. A reset is drawn once per connection, at one send drawn among its first 1023, so
  most connections survive and a long one is more likely reset. `net-blackout=START+LENGTH`
  holds TCP data and loses datagrams for LENGTH ms (`--fault net-blackout=0..60000+1000..10000`:
  a window of 1 to 10 s somewhere in the first minute). There is no network outside the run:
  servers and clients must all run inside it.
- **Memory.** `--faults mem` is for a program that handles allocation failure;
  `--fault mem-limit-mb=N` fails memory requests past N MiB.
- **Paths.** `--fault path-swap-permille=P` changes a `/work` path between a process's check of
  it (`stat`, `access`, `open`) and its use: a symlink, a rename into its place, a rename away.
  In no class: it models another writer, so a finding is a bug only where the program must
  withstand one (a server reading a shared directory).

A failing group says which classes injected in every failing run, and in none (`faults in every
failing run: fs-short      in none: fs-error, fsync-error`). `patina minimize RUNDIR` then drops
and halves the run's fault settings while it still fails the same way, and prints the command
for the reduced run. `result.json`'s `faults` has the resolved plan, and per class the calls it
could act on and the faults it injected.
