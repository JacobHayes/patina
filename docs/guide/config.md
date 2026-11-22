# Config: every patina.toml key

`patina.toml` in the current directory (or `--config FILE`) holds the same settings as the flags,
and a few only it holds; flags override it, and an unknown key is an error. Paths in it are
relative to the file, but `run` and `check` are commands, relative to where patina is started.
`--config RUNDIR/run.json` takes every setting of an earlier run. With `[machine.main] run` set,
`patina sweep` needs no other arguments.

```toml
[run]
cpus = 2

[machine.main]
run = ["./acklog"]

[faults]
faults = ["disk", "crash"]
fsync-error-permille = 0
```

<!-- generated: config (crates/patina-cli/src/config.rs, TOML_KEYS); a unit test keeps it equal -->
| `[run]` | Value | Default | Sets |
|---|---|---|---|
| `env` | `{ K = "V" }` | none | added to the guest environment, as `--env` |
| `mounts` | `["SRC:DST[:copy]", ...]` | none | as `--mount` |
| `stdin` | `"FILE"` | empty | as `--stdin` |
| `check` | `"CMD ARGS"` | none | as `--check` |
| `ok-exit` | `[N, "N:CLASS,..."] or "any"` | none | as `--ok-exit` |
| `timeout` | `SECONDS` | 600 | as `--timeout`: wall time |
| `cpus` | `N` | 4 | the CPU count the program sees (1 to 64) |
| `disk-mb` | `MIB` | 256 | the size of each sandbox filesystem (`/work`, `/tmp`, copied mounts) |
| `time-limit` | `SECONDS` | 3600 | virtual time after which the run ends `liveness` |
| `log-limit` | `MIB` | 1024 | log size at which the run ends `liveness` (a livelock) |
| `check-timeout` | `SECONDS` | 60 | wall time a checker may take |
| `setup` | `"CMD ARGS", ["CMD", "ARG", ...] or "mark"` | none | as `--setup`: run first, without faults; `mark`: the program marks `setup-complete` |
| `finally` | `"CMD ARGS" or ["CMD", "ARG", ...]` | none | as `--finally`: the final check, run with the faults stopped |

| `[faults]` | Value | Default | Sets |
|---|---|---|---|
| `faults` | `["CLASS[@MACHINE,...]", ...]` | none | as `--faults` |
| `KEY` | `VALUE` | none | any fault key, as `--fault KEY=VALUE` (`patina run --fault help`) |
| `fs-model` | `"ext4-ordered" or "posix-strict"` | ext4-ordered | what a machine crash keeps |

| `[sched]` | Value | Default | Sets |
|---|---|---|---|
| `preempt` | `"points" or "traps"` | points | `traps`: switch threads only at system calls, spin hints and spin probes (a diagnostic) |
| `preempt-permille` | `P` | 100 | the chance in 1000 that a system call switches threads |

| `[sweep]` | Value | Default | Sets |
|---|---|---|---|
| `known` | `"FILE"` | none | as `--known` |
| `allow-unmet` | `["LABEL", ...]` | none | as `--allow-unmet` |
| `crash-pairs` | `K` | off | with `--crash-points` and machines: crash a second machine at each of its next K points after a first crash |

| `[machine.NAME]` | Value | Default | Sets |
|---|---|---|---|
| `run` | `["CMD", "ARG", ...]` | required | the command Patina starts at each of its boots; [machine.main] run is the command after `--` |
| `env` | `{ K = "V" }` | none | added to the run's environment |
| `disk` | `"DIR[:GUEST]"` | empty | its disk's starting files (main's: as `--disk`) |
| `restart` | `"crash", "always" or "never"` | crash | after which downs the seed restarts it (`always`: also after it exits within `ok-exit`) |
| `ok-exit` | `N or [N, ...]` | [0] | exit statuses that only stop the machine |
| `max-boots` | `N` | the run's | the most boots the seed's crashes give it (1 to 64) |
| `disk-mb` | `N or "A..B"` | the run's | its filesystems' size, drawn per seed from a range |
| `count` | `N` | 1 | N machines of this table, named NAME1 to NAMEN |
| `faults` | `true or false` | true | `false`: no faults of its own, as main |
<!-- end generated -->

Fault keys and their ranges: `patina run --fault help`. Options: `patina COMMAND --help`.
