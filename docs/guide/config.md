# Config: every patina.toml key

`patina.toml` in the current directory (or `--config FILE`) holds the same settings as the flags,
and a few only it holds; flags override it, and an unknown key is an error. Paths in it are
relative to the file, but `cmd` and `check` are commands, relative to where patina is started.
`--config RUNDIR/run.json` takes every setting of an earlier run. With `cmd` set, `patina sweep`
needs no other arguments.

```toml
[run]
cmd = ["./acklog"]
cpus = 2

[faults]
faults = ["disk", "crash"]
fsync-error-permille = 0
```

<!-- generated: config (crates/patina-cli/src/config.rs, TOML_KEYS); a unit test keeps it equal -->
| `[run]` | Value | Default | Sets |
|---|---|---|---|
| `cmd` | `["CMD", "ARG", ...]` | none | the program and its arguments, as after `--` |
| `env` | `{ K = "V" }` | none | added to the guest environment, as `--env` |
| `mounts` | `["SRC:DST[:copy]", ...]` | none | as `--mount` |
| `work` | `"DIR[:GUEST]"` | empty | as `--work` |
| `stdin` | `"FILE"` | empty | as `--stdin` |
| `check` | `"CMD ARGS"` | none | as `--check` |
| `ok-exit` | `[N, "N:CLASS,..."] or "any"` | none | as `--ok-exit` |
| `timeout` | `SECONDS` | 600 | as `--timeout`: wall time |
| `cpus` | `N` | 4 | the CPU count the program sees (1 to 64) |
| `disk-mb` | `MIB` | 256 | the size of each sandbox filesystem (`/work`, `/tmp`, copied mounts) |
| `time-limit` | `SECONDS` | 3600 | virtual time after which the run ends `liveness` |
| `log-limit` | `MIB` | 1024 | log size at which the run ends `liveness` (a livelock) |
| `check-timeout` | `SECONDS` | 60 | wall time a checker may take |

| `[faults]` | Value | Default | Sets |
|---|---|---|---|
| `faults` | `["CLASS[@NODE,...]", ...]` | none | as `--faults` |
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
| `crash-pairs` | `K` | off | with `--crash-points` and nodes: crash a second node at each of its next K points after a first crash |

| `[node.NAME]` | Value | Default | Sets |
|---|---|---|---|
| `cmd` | `["CMD", "ARG", ...]` | required | the node's program |
| `env` | `{ K = "V" }` | none | added to the run's environment |
| `work` | `"DIR[:GUEST]"` | empty | its work tree's starting files, as `--work` |
| `restart` | `"crash", "always" or "never"` | crash | after which downs the seed restarts it (`always`: also after it exits within `ok-exit`) |
| `ok-exit` | `N or [N, ...]` | [0] | exit statuses that only stop the node |
| `max-incarnations` | `N` | the run's | the most boots the seed's crashes give it (1 to 64) |
| `disk-mb` | `N or "A..B"` | the run's | its filesystems' size, drawn per seed from a range |
| `count` | `N` | 1 | N nodes of this table, named NAME1 to NAMEN |
| `faults` | `true or false` | true | `false`: no faults of its own, as the driver |
<!-- end generated -->

Fault keys and their ranges: `patina run --fault help`. Options: `patina COMMAND --help`.
