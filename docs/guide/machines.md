# Machines: several machines in one run

A run can hold several machines. The command after `--` runs on machine **main** (or give it as
`[machine.main] run`). Main is a machine like any other, and the seed's faults act on every
machine, main included; main differs only in that the run ends with its exit status. A main that
is the test's driver, not part of the system under test, writes `[machine.main] faults = false`
(below). Each other `[machine.NAME]` table in `patina.toml`, or `--machine NAME='CMD ARGS'`,
adds a machine whose program starts with the run, before main's:

<!-- transcript machines-kv
dir: /tmp/machines
setup: mkdir g && cp "$GUESTS/kv.py" "$GUESTS/patina.py" g/
setup: printf '[machine.primary]\nrun = ["python3", "/guest/kv.py", "primary"]\n\n[machine.backup]\nrun = ["python3", "/guest/kv.py", "backup"]\n' >patina.toml
-->
```text
$ cat patina.toml
[machine.primary]
run = ["python3", "/guest/kv.py", "primary"]

[machine.backup]
run = ["python3", "/guest/kv.py", "backup"]
$ patina run --mount g:/guest:copy -- python3 /guest/kv.py main
ok (exit): the program exited 0
guest: exit 0
machines: primary 10.0.0.2 running, backup 10.0.0.3 running; net: 1 cuts, 1 heals, 1 held, none cut at the end
run directory: /tmp/machines/patina-out/run-0
replay: patina replay /tmp/machines/patina-out/run-0
```

`kv.py` (in `tests/guests/machines`) is a store whose primary sends each write to the backup; the
main writes, cuts the link between them, sees the next write wait, heals it, and checks both
agree. To test a distributed system, put the system under test on machines, give each a `ready`
probe (below), and make main the harness, out of the faults: drive the workload, call `patina
ctl settle`, then check the system.

## Settle, then check

`patina ctl settle [SECONDS]` in main's script (or the SDK's `control("settle")`) ends the seed's
faults for the rest of the run and waits for the system to recover: the seed's partitions heal,
the machines it paused resume, the machines it took down boot at once, and the call returns when
every machine is ready again (started and not paused). What the script itself did stays: its
cuts, its pauses, and a machine it crashed or killed, which stays down and is not waited for. A
machine not ready SECONDS of virtual time (default 60) after the faults stopped ends the run
`liveness` (stop `settle`), naming it: the system did not recover. Crash points stop counting at
settle, a second call does nothing, and `result.json`'s `settle` holds the point (sequence
number and virtual time). What follows the call is the check, against a quiet, recovered
system:

<!-- transcript machines-settle
dir: /tmp/settle
setup: mkdir g && cp "$GUESTS/phases.py" g/
setup: printf '[machine.main]\nfaults = false\n\n[machine.a]\nrun = ["python3", "/guest/phases.py", "serve"]\n\n[machine.b]\nrun = ["python3", "/guest/phases.py", "serve", "lazy"]\n' >patina.toml
exit: 0 1
exact-only: one seed's run
-->
```text
$ cat patina.toml
[machine.main]
faults = false

[machine.a]
run = ["python3", "/guest/phases.py", "serve"]

[machine.b]
run = ["python3", "/guest/phases.py", "serve", "lazy"]
$ patina run --seed 5 --mount g:/guest:copy --faults crash --fault crash-gap-ms=1000..4000 --fault max-boots=8 -- sh -c 'python3 /guest/phases.py work 10 a b && patina ctl settle && python3 /guest/phases.py check 10 a b'
failure (exit): exit status 1
guest: exit 1
settled: seq 7352 t=106215ms
faults on: a, b
machines: a 10.0.0.2 running after 1 down, 2 boots, b 10.0.0.3 running after 1 down, 2 boots
guest stderr (1 lines, /tmp/settle/patina-out/run-5/boot-1/stderr):
  FAIL: check: b lost acknowledged puts [3, 4, 5, 6]
faults injected: 2 (crash 2)
last injected:
  seq 4277 t=101147ms crash machine=a kind=machine lost: 0 missing, 0 changed, 0 back
  seq 4304 t=101779ms crash machine=b kind=machine object=/work/log lost: 0 missing, 1 changed, 0 back
run directory: /tmp/settle/patina-out/run-5
replay: patina replay /tmp/settle/patina-out/run-5
explain: patina explain /tmp/settle/patina-out/run-5
```

`phases.py` (in `tests/guests/machines`) stores puts; `work` puts 1 to 10 on both machines and
`check` polls each until it answers, then looks for every acknowledged put. Main, the driver,
has `faults = false`, so `--faults crash` crashes a and b and the run says so (`faults on:`).
With `lazy`, b acknowledges a put before its `fsync`, and the check after settle finds what b's
machine crash lost. Settle works the same with one machine: under `--faults crash`, `-- sh -c './app && patina
ctl settle && ./verify'` reruns `./app` at each boot after a crash and runs `./verify` once,
after the last.

**What a machine has of its own:** a disk, `/tmp`, its hostname and `PATINA_MACHINE` (its name;
`main` also in a run with no machines declared), `PATINA_BOOT` (its boot, from 1), a port space, a loopback, and the address `10.0.0.K` (main `10.0.0.1`, the first machine
`10.0.0.2`); `/etc/hosts` names every machine. `/usr`, the mounts and the program's directory are
shared and read-only. A listener on `0.0.0.0` is reachable from every machine, one on `127.0.0.1`
only from its own. A machine's output is in `RUNDIR/machine/NAME/boot-K/`. Up to 15 machines;
`count = N` in a table makes N of them. The machine keys are in `patina guide config`.

## Waiting for a machine: `ready`

A server needs a moment before it serves. `ready = "CMD ARGS"` in a machine's table is a probe
Patina runs on that machine, from its first boot, every 100 ms of virtual time until it exits 0.
Main's command starts, and the seed's faults begin, when every machine is ready; a machine
without a probe is ready when it starts. `patina wait HOST:PORT` is a probe for a server: one TCP
connect, exit 0 when it is accepted (`:PORT` is the machine's own port).

<!-- transcript machines-ready
dir: /tmp/ready
setup: mkdir g && cp "$GUESTS/phases.py" "$GUESTS/slow.py" g/
setup: printf '[machine.srv]\nrun = ["python3", "/guest/slow.py"]\nready = "patina wait :7000"\n' >patina.toml
exit: 0 0 0 1
-->
```text
$ cat patina.toml
[machine.srv]
run = ["python3", "/guest/slow.py"]
ready = "patina wait :7000"
$ patina sweep --seeds 1..8 --mount g:/guest:copy --fault fsync-error-permille=50 -- python3 /guest/phases.py work 5 srv
sweep: 70.0 KiB kept in /tmp/ready/patina-out/sweep
patina sweep: 8 runs, 0 findings in 0 groups, 8 ok   (0.2s, 8 jobs)
outcomes: ok 8
machines: main, srv in 8 runs; net: 0 cuts, 0 heals, 0 held over them
$ grep -v ready patina.toml >plain.toml
$ patina sweep --seeds 1..8 --config plain.toml --out patina-out/plain --mount g:/guest:copy --fault fsync-error-permille=50 -- python3 /guest/phases.py work 5 srv
...
patina sweep: 8 runs, 6 findings in 1 group, 2 ok   (0.3s, 8 jobs)
...
failure exit [machine srv]: FAIL: serve: start: [Errno N] Input/output error; exit 1
...
```

`slow.py` makes 20 synced writes before it serves `phases.py`'s store, and exits at a failed one. Without `ready`
the fsync errors reach that start, and the sweep's findings are the start's, not the store's; with
it the faults begin once the server accepts a connection. `result.json`'s `ready` has the virtual
time (ms) each machine was first ready.

A probe on main holds the faults, not main's command, until it passes: a test whose own setup
must finish first writes `[machine.main] ready = "test -e /tmp/setup-done"` and creates the file
when done; a client and server on main alone (`-- sh -c './server & ./client'`) take
`[machine.main] ready = "patina wait :7000"`. Probes run at the first boot only: after a restart
nobody is told, clients retry. `ready` and `--setup` cannot be combined.

A probe that has not passed 60 s of virtual time after boot, or a machine whose `run` ends before
it is ready, ends the run `error`, stop `ready`: the faults never began. The machine's stderr has
what the probe last said:

<!-- transcript machines-never-ready
dir: /tmp/ready
setup: printf '[machine.srv]\nrun = ["python3", "/guest/phases.py", "serve"]\nready = "test -e /work/ready"\n' >never.toml
exit: 2
-->
```text
$ patina run --config never.toml --mount g:/guest:copy -- python3 /guest/phases.py work 5 srv
error (ready): machine srv was not ready 60 s after boot: its probe `test -e /work/ready` never exited 0 (what it last said is in srv's stderr); the faults had not begun
machines: srv 10.0.0.2 running
srv stderr (1 lines, /tmp/ready/patina-out/run-0/machine/srv/boot-1/stderr):
  patina: ready probe `test -e /work/ready`: exit 1
...
```

## Setup, main command, final check with machines

The machines boot first, without faults. The setup (`--setup`) then runs as main's first
command, on main's machine; when it exits 0 the main command starts and the faults with it.
When the main command ends ok the faults stop for good: partitions and cuts heal, paused machines
resume, and every down machine whose restart policy has a restart scheduled starts at once (a machine
a control call took down stays down). Only then does
the final check (`--finally`) start; a machine may still be booting, so the check polls:

<!-- transcript machines-phases
dir: /tmp/phases-machines
setup: mkdir g && cp "$GUESTS/phases.py" g/
setup: printf '[machine.main]\nfaults = false\n[machine.a]\nrun = ["python3", "/guest/phases.py", "serve"]\n[machine.b]\nrun = ["python3", "/guest/phases.py", "serve", "lazy"]\n' >patina.toml
exit: 1
exact-only: one seed's run
-->
```text
$ patina run --seed 4 --mount g:/guest:copy --faults crash,partition --fault crash-gap-ms=1000..4000 --fault max-boots=8 --setup 'python3 /guest/phases.py check 0 a b' --finally 'python3 /guest/phases.py check 10 a b' -- python3 /guest/phases.py work 10 a b
failure (finally): the final check (--finally) exited 1
guest: exit 0
phases: setup exit 0, main exit 0, finally exit 1
faults on: a, b
machines: a 10.0.0.2 running after 1 down, 2 boots, b 10.0.0.3 running after 1 down, 2 boots
finally stderr (1 lines, /tmp/phases-machines/patina-out/run-4/boot-1/stderr from byte 0):
  FAIL: check: b lost acknowledged puts [1, 2, 3, 4, 5, 6, 7, 8, 9]
faults injected: 2 (crash 2)
last injected:
  seq 11641 t=101745ms crash machine=a kind=machine lost: 0 missing, 0 changed, 0 back
  seq 11667 t=102608ms crash machine=b kind=machine object=/work/log lost: 0 missing, 1 changed, 0 back
run directory: /tmp/phases-machines/patina-out/run-4
replay: patina replay /tmp/phases-machines/patina-out/run-4
explain: patina explain /tmp/phases-machines/patina-out/run-4
```

With `lazy`, b acknowledges a put before its `fsync`: the main command sees nothing wrong, and
the final check finds what b's machine crashes lost.

## Main's control: `patina ctl`

Main acts on the network and the machines with control calls, the fault classes' own actions:
`patina ctl WORDS` in a script (`patina` is on the `PATH` of every run; without machines every call
but `settle` is refused), or the SDK's `control("WORDS")`.

| Words | |
|---|---|
| `partition A B`, `partition --from A --to B` | cut both directions between machine sets A and B, or one |
| `heal A B`, `heal` | heal those links, or every cut |
| `crash NAME` | crash the machine: unsynced data may be lost, its peers hear nothing |
| `kill NAME` | kill every process of the machine; its disk is kept |
| `start NAME` | start a machine that is down |
| `pause NAME`, `resume NAME` | freeze the machine and let it run again |
| `clock NAME +90s` | move the machine's realtime clock |
| `settle [SECONDS]` | end the seed's faults and wait until every machine is ready (above) |

A set is machine names joined by commas (`main` included), or `rest`. A cut holds TCP data, as a
pulled cable does, until a heal or the sender's timeout; datagrams across it are lost.

## The seed's faults on machines

One rule, whatever the number of machines: a class or key without `@` acts on every machine,
main included, and on every link between them. Main can be paused, clock-stepped, cut off and
given disk faults like the others; a crash or kill of main beside other machines is not
available yet, and is refused (exempt main, or name the machines).

- `--faults net`: delays, resets and the rest on the links between machines with faults, each
  one's loopback included.
- `--faults partition`: cuts between groups of machines for a while (two machines with faults or
  more).
- `--faults pause`: a machine frozen for a while; its peers see a live machine that does not answer.
- `--faults clock`: each boot of a machine draws a realtime clock offset.
- `--faults crash` or `--faults kill`: machine crashes or process kills at drawn times, each
  followed by a restart (`--fault crash-gap-ms=2000..10000` for frequent ones in a short run).
- `--faults disk`, `mem`, `buggify`: each machine's own.

`@MACHINE,...` scopes a class or key to machines: `--faults crash@db`, `--fault
fsync-error-permille=5@a,main`. `[machine.NAME] faults = false` keeps a machine out of all the
seed's faults, its links included; a test driver on main writes `[machine.main] faults = false`.
The run prints `faults on:` with the machines its faults act on, and says so when every machine
has `faults = false`. A group's `machines:` line says which machines were down or partitioned in its failing runs.

<!-- transcript machines-sweep
dir: /tmp/q3
setup: mkdir g && cp "$GUESTS/q3.py" "$GUESTS/patina.py" g/
setup: { printf '[machine.main]\nfaults = false\n\n'; for n in n1 n2 n3; do printf '[machine.%s]\nrun = ["python3", "/guest/q3.py", "%s", "nosync"]\n\n' $n $n; done; } >patina.toml
exit: 1
release-only: a sweep of eight runs of a three-machine cluster
-->
```sh
patina sweep --seeds 1..8 --mount g:/guest --faults net,partition,pause,clock,crash --fault crash-gap-ms=2000..10000 -- python3 /guest/q3.py main 30
```

`q3.py` is a store on three machines and its main a checking client (`faults = false`); with `nosync` a machine acknowledges a write before it is on
disk, and a write the cluster acknowledged is lost when the machines that had it crash. Without
`nosync` the same sweep is clean.

## Every crash point of every machine

Each machine counts crash points on its own disk. `patina sweep --crash-points` (with `--faults
crash@a,b` to name machines) crashes one machine at each of its points in turn; `[sweep]
crash-pairs = K` also crashes a second machine at each of its next K points after every first
crash. Give large runs `--crash-points=N`. `--fault crash-at=N@MACHINE` crashes one machine at one
point.

<!-- transcript machines-points
release-only: a sweep of a seed's 30 crash points
dir: /tmp/ack2
setup: mkdir g && cp "$GUESTS/ack2.py" "$GUESTS/patina.py" g/
setup: printf '[run]\nsetup = "mark"\n[machine.main]\nfaults = false\n[machine.a]\nrun = ["python3", "/guest/ack2.py", "a"]\n[machine.b]\nrun = ["python3", "/guest/ack2.py", "b", "early"]\n' >patina.toml
exit: 1
-->
```text
$ patina sweep --seeds 1 --crash-points -j 4 --mount g:/guest:copy -- python3 /guest/ack2.py main 3
...
crash points: 30 of 30 tried (a 15 of 15, b 15 of 15)
...
```

`ack2.py` forwards each put from machine a to b and acknowledges it once b answers; with `early`, b
answers before its `fsync`, and a crash of b loses an acknowledged put. Its main marks the end
of its setup itself (`setup = "mark"` under `[run]`), so only the puts' points count.

## In the logs

`result.json`'s `machines` lists each machine with its address, boots and downs (how, when, for
how long, what its disk lost), its pauses and clock, and the partitions. `patina log events`
names each thread's machine and adds `machine` and `net` events; `patina explain` tells the story by
machine. Seeds, `replay` and `verify` work as on one machine: one scheduler, one clock, one log.
