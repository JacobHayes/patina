# Faults: the classes, the keys, and when faults act

Faults are drawn from the seed like everything else, so every finding replays. Name the kinds of
fault, the classes; each class turns on settings whose values are ranges, and each seed draws a
value in each range, so one sweep covers gentle and harsh settings. Add one class at a time,
starting from the bug you suspect: a run that meets every fault at once fails in ways that say
little.

    --faults CLASS[,CLASS...][@MACHINE,...]  repeatable; [faults] faults = ["CLASS", ...]
    --fault  KEY=VALUE[@MACHINE,...]         repeatable; [faults] KEY = VALUE

`patina run --fault help` prints every class with the ranges it turns on, and every key.

| Class | What the seed does |
|---|---|
| `disk` | errors, short reads and writes, failed write-backs and delays on files under `/work`, pipes and unix sockets: each an error Linux can return for that call |
| `net` | delays, split deliveries, connection resets and refused connects; for datagrams, drops, duplicates and reordering |
| `mem` | `ENOMEM` from memory requests, `EAGAIN` from thread creation |
| `buggify` | the program's own fault points fire (`patina guide sdk`) |
| `crash` | the machine crashes and the program restarts on what reached the disk (`patina guide crashes`) |
| `kill` | the program's processes are killed and restarted; the disk keeps everything |
| `partition` | links between machines are cut for a while (`patina guide machines`) |
| `pause` | a machine stops for a while, its sockets open |
| `clock` | a machine's realtime clock is off by a drawn amount |
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
4. **Machines.** A class or key without `@` acts on every machine, main included, and on the
   links between them, however many machines the run has; `@a,b` names machines (`patina guide
   machines`). `[machine.NAME] faults = false` exempts a machine from all of them: a main that
   runs only the test writes `[machine.main] faults = false`. `partition`, `pause` and `clock` exist only
   with machines. A run prints `faults on:` with the machines its faults act on.

<!-- transcript not-applicable
dir: /tmp/sockets
setup: cp "$GUESTS/sockets" .
-->
```text
$ patina sweep --seeds 1..20 --faults net --out patina-out/tcp -- ./sockets chunk correct
...
faults: not applicable (a class's, nothing to act on in any run): net-drop, net-dup, net-reorder
```

## When faults act: `ready` opens the window, `settle` closes it

The seed's faults act in one window of the run, and the test says where it opens and closes:

- **It opens when every machine is ready.** A machine's `ready` probe is a command Patina runs on
  it every 100 ms of virtual time until it exits 0 (`patina guide machines`); a machine without
  one is ready when it starts, so with no probe the window is open from the start. A server
  takes `ready = "patina ctl wait :7000"`; a test whose own setup must finish first puts a probe on
  main, `[machine.main] ready = "test -e /tmp/setup-done"`, and creates the file when the setup
  is done. Crash points count only inside the window, so `--crash-points` and `minimize` crash
  only the work.
- **It closes at `patina ctl settle`** in the test (the SDK's `control("settle")`), or at the
  run's end. Settle ends the seed's partitions and pauses, boots at once the machines the seed
  took down, runs the machines' probes again, and returns when every machine is ready: the
  system has recovered. What the test's own control calls did stays.
- **The final check is the test's own code after settle**, against the live, quiet system:
  `-- sh -c './work && patina ctl settle && ./verify'`. Under `--faults crash` the command after
  `--` starts again at each boot, so `./work` runs again after a crash and `./verify` runs once,
  after the last. `--check` is the other kind of check: it runs on the host after the run, over
  its recorded output and final disk (`patina guide checks`).

A client and a server on one machine, the faults held until the server listens:

<!-- transcript settle-one
dir: /tmp/settle-one
setup: mkdir g && cp "$GUESTS/phases.py" g/
setup: printf '[machine.main]\nready = "patina ctl wait :7000"\n' >patina.toml
exact-only: the faults one seed draws
-->
```text
$ cat patina.toml
[machine.main]
ready = "patina ctl wait :7000"
$ patina run --mount g:/guest:copy --faults disk,net -- sh -c 'python3 /guest/phases.py serve & python3 /guest/phases.py work 20 127.0.0.1 && patina ctl settle && python3 /guest/phases.py check 20 127.0.0.1'
ok (exit): the program exited 0
guest: exit 0
settled: seq 9882 t=105534ms
faults on: main
faults injected: 45 (fs-delay 1, net-delay 43, net-reset 1)
run directory: /tmp/settle-one/patina-out/run-0
replay: patina replay /tmp/settle-one/patina-out/run-0
```

`phases.py` (in `tests/guests/machines`) is a store: `serve` answers puts on :7000, `work` puts
1 to 20 and retries each until it is acknowledged, and `check` looks for every acknowledged put.
`result.json`'s `ready` has when each machine was first ready and `settle` where the faults
ended (sequence number and virtual time).

A starting state the test needs but does not test belongs in the disk: `--disk DIR` (or
`[machine.NAME] disk`) starts a machine's disk as a copy of DIR. Put a system under test on its
own machines and main is the test (`patina guide machines`):

<!-- no-run primary-standby: needs a database to test, which the repository does not ship -->
```sh
cat >patina.toml <<'TOML'
[machine.main]
faults = false

[machine.primary]
run   = "./db --role primary --peer standby"
ready = "patina ctl wait :5432"

[machine.standby]
run   = "./db --role standby --peer primary"
ready = "patina ctl wait :5432"
TOML
cat >test.sh <<'SH'
./workload primary,standby || exit
patina ctl settle
./verify primary,standby
SH
patina sweep --seeds 1..200 --faults net,partition,crash -- sh test.sh
```

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
