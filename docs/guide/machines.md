# Machines: several machines in one run

A run can hold several machines. The command after `--` runs on machine **main** (or give it as
`[machine.main] run`): the seed's faults leave main alone unless one names it (`@main`), and the
run ends with its exit status. Each other `[machine.NAME]` table in `patina.toml`, or `--machine NAME='CMD ARGS'`,
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
agree. To test a distributed system, put the system under test on machines and make main the
harness, in three commands: the setup waits for the system, the main command drives the
workload, the final check verifies (`patina guide faults`).

**What a machine has of its own:** a disk, `/tmp`, its hostname (its name), a port
space, a loopback, and the address `10.0.0.K` (main `10.0.0.1`, the first machine
`10.0.0.2`); `/etc/hosts` names every machine. `/usr`, the mounts and the program's directory are
shared and read-only. A listener on `0.0.0.0` is reachable from every machine, one on `127.0.0.1`
only from its own. A machine's output is in `RUNDIR/machine/NAME/boot-K/`. Up to 15 machines;
`count = N` in a table makes N of them. The machine keys are in `patina guide config`.

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
setup: printf '[machine.a]\nrun = ["python3", "/guest/phases.py", "serve"]\n[machine.b]\nrun = ["python3", "/guest/phases.py", "serve", "lazy"]\n' >patina.toml
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
  FAIL: check: b lost acknowledged puts [4, 5, 6, 7, 8, 9]
faults injected: 2 (crash 2)
last injected:
  seq 11550 t=101745ms crash machine=a kind=machine lost: 0 missing, 0 changed, 0 back
  seq 11575 t=102608ms crash machine=b kind=machine object=/work/log lost: 0 missing, 1 changed, 0 back
run directory: /tmp/phases-machines/patina-out/run-4
replay: patina replay /tmp/phases-machines/patina-out/run-4
explain: patina explain /tmp/phases-machines/patina-out/run-4
```

With `lazy`, b acknowledges a put before its `fsync`: the main command sees nothing wrong, and
the final check finds what b's machine crashes lost.

## Main's control: `patina ctl`

Main acts on the network and the machines with control calls, the fault classes' own actions:
`patina ctl WORDS` in a script (`patina` is on the `PATH` of every run; without machines every call
is refused), or the SDK's `control("WORDS")`.

| Words | |
|---|---|
| `partition A B`, `partition --from A --to B` | cut both directions between machine sets A and B, or one |
| `heal A B`, `heal` | heal those links, or every cut |
| `crash NAME` | crash the machine: unsynced data may be lost, its peers hear nothing |
| `kill NAME` | kill every process of the machine; its disk is kept |
| `start NAME` | start a machine that is down |
| `pause NAME`, `resume NAME` | freeze the machine and let it run again |
| `clock NAME +90s` | move the machine's realtime clock |

A set is machine names joined by commas (`main` included), or `rest`. A cut holds TCP data, as a
pulled cable does, until a heal or the sender's timeout; datagrams across it are lost.

## The seed's faults on machines

- `--faults net`: delays, resets and the rest on the links between machines (not main's:
  `--faults net@main` adds them; `partition@main` likewise).
- `--faults partition`: cuts between groups of machines for a while (two machines or more).
- `--faults pause`: a machine frozen for a while; its peers see a live machine that does not answer.
- `--faults clock`: each boot of a machine draws a realtime clock offset.
- `--faults crash` or `--faults kill`: machine crashes or process kills at drawn times, each
  followed by a restart (`--fault crash-gap-ms=2000..10000` for frequent ones in a short run).
- `--faults disk`, `mem`, `buggify`: each machine's own.

`@MACHINE,...` scopes a class or key to machines: `--faults crash@db`, `--fault
fsync-error-permille=5@a,main`. `[machine.NAME] faults = false` keeps a machine out of unscoped
faults. A group's `machines:` line says which machines were down or partitioned in its failing runs.

<!-- transcript machines-sweep
dir: /tmp/q3
setup: mkdir g && cp "$GUESTS/q3.py" "$GUESTS/patina.py" g/
setup: for n in n1 n2 n3; do printf '[machine.%s]\nrun = ["python3", "/guest/q3.py", "%s", "nosync"]\n\n' $n $n; done >patina.toml
exit: 1
release-only: a sweep of eight runs of a three-machine cluster
-->
```sh
patina sweep --seeds 1..8 --mount g:/guest --faults net,partition,pause,clock,crash --fault crash-gap-ms=2000..10000 -- python3 /guest/q3.py main 30
```

`q3.py` is a store on three machines; with `nosync` a machine acknowledges a write before it is on
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
setup: printf '[run]\nsetup = "mark"\n[machine.a]\nrun = ["python3", "/guest/ack2.py", "a"]\n[machine.b]\nrun = ["python3", "/guest/ack2.py", "b", "early"]\n' >patina.toml
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
