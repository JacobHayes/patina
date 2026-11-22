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

## When faults act: setup, main command, final check

Most tests have a setup that is not under test (start the server, create the schema, load the
fixture) and a final check that should see a settled system (read everything back, compare
replicas). A run has up to three commands, run one after the other inside it: the same sandbox,
seed and log.

    --setup 'CMD ARGS'      [run] setup = "CMD ARGS" or ["CMD", "ARG", ...]
    -- CMD ARGS             the main command
    --finally 'CMD ARGS'    [run] finally = "CMD ARGS" or ["CMD", "ARG", ...]

- **The setup** runs without faults or crash points. When it exits 0 the main command starts,
  and what it left running (a server started in the background) keeps running, faulted from
  then on. A setup that exits nonzero, is killed, or hangs until the run's limit (`[run]
  time-limit`, `--timeout`) ends the run `error` (stop `setup`), showing its output: a harness
  problem, not a finding. After a machine crash the machine runs the setup again, then the main
  command, so a setup must be safe to repeat on the crashed disk; a setup that fails there is a
  finding (stop `setup`).
- **The main command** runs under the faults; crash points count only in it, so
  `--crash-points` and `minimize` crash only the work.
- **The final check** runs only if the main command ended by itself with an ok status (0 or an
  `--ok-exit` status); otherwise the run ends with the main command's outcome. Before it starts
  the faults stop for the rest of the run: partitions and cuts heal, paused nodes resume, a node
  whose restart policy has a restart scheduled starts at once (one a control call took down stays
  down), and nothing more is injected. A nonzero exit is a
  `failure` (stop `finally`), with its output. Recovery takes time, so make the check poll
  until the system answers rather than assume it already does.

`--finally` runs inside the run against the live system; `--check` runs on the host after the
run, over its recorded output and final disk (`patina guide checks`).

A run with a setup and a final check is as deterministic as one without: the same seed gives the
same run, and `replay` repeats it exactly. The only difference is that no fault is injected in
the setup or the final check.

<!-- transcript phases
dir: /tmp/phases
setup: mkdir g && cp "$GUESTS/phases.py" g/
exact-only: the faults one seed draws
-->
```text
$ patina run --mount g:/guest:copy --faults disk,net --setup 'python3 /guest/phases.py start' --finally 'python3 /guest/phases.py check 20 127.0.0.1' -- python3 /guest/phases.py work 20 127.0.0.1
ok (exit): the program exited 0
guest: exit 0
phases: setup exit 0, main exit 0, finally exit 0
faults injected: 42 (net-delay 41, net-reset 1)
run directory: /tmp/phases/patina-out/run-0
replay: patina replay /tmp/phases/patina-out/run-0
```

`phases.py` (in `tests/guests/nodes`) starts a store in the background, puts records through it,
and checks they are all there. `result.json`'s `phases` has each command's start and end
(sequence numbers), its exit and where its output begins; `patina explain` shows the boundaries.

**Put the system under test on a node; the driver is the harness**: its setup waits for the
system, its main command drives the workload, its final check verifies (`patina guide nodes`).
A run with one node costs about what a run without nodes does.

<!-- no-run node-harness: needs a database to test, which the repository does not ship -->
```sh
patina sweep --seeds 1..200 --faults all,crash --node db='./db --listen :7000' \
    --setup './wait-for db:7000' --finally './verify db:7000' -- ./workload db:7000
```

**A program that is its own harness** can mark the end of its setup itself: declare it with
`[run] setup = "mark"` (`--setup mark`) and call the SDK's `setup_complete()` (`patina guide
sdk`); faults act from the mark. A mark the run does not declare, or a declared one never
reached, ends the run `error` naming the fix; a program named `mark` is given by its path
(`--setup ./mark`). `faults_done()` stops injecting from where it is called and ends the seed's
partitions and pauses; it needs no declaration, and unlike `--finally` it neither heals cuts
made by control calls nor starts down nodes.

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
