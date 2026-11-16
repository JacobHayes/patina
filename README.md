# Patina

**Weather your code into a fine protective patina — before production does.**

Patina runs a Linux x86_64 program many times, each run under a seed that decides thread
order, the clock, randomness, and which disk, network and crash faults the program meets.
The same seed gives the same run, so a bug that shows up once in a thousand runs becomes a
seed you can replay as often as you like. Your program runs unmodified: no rebuild, no
special linking, any language.

Patina is experimental. Linux x86_64 only. It needs `bwrap` (bubblewrap) and unprivileged
user namespaces.

Changes in 0.6: macOS, `patina test` and `patina campaign` are gone. Any executable runs as
it is (`patina run -- ./prog`), and `patina sweep` runs many seeds.

## Install

From a checkout, with Rust (rustup reads the pinned toolchain from `rust-toolchain.toml`):

```sh
git clone https://github.com/JacobHayes/patina && cd patina
cargo install --locked --path crates/patina-cli
patina doctor
```

`patina doctor` checks the host and prints the fix for anything missing. The last line
should read `this host can run patina`. On Ubuntu 24.04 the two fixes are:

```sh
sudo apt-get install -y bubblewrap
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## First run

Give Patina any program and its arguments after `--`. `examples/quickstart` is a small Rust
program that runs three jobs on threads and checks their results come back in job order.

```sh
cd examples/quickstart && cargo build
patina run -- target/debug/jobs fixed
```

```text
ok (exit): the program exited 0
guest: exit 0
run directory: /tmp/patina/examples/quickstart/patina-out/run-0
replay: patina replay /tmp/patina/examples/quickstart/patina-out/run-0
```

The program's own output is in the run directory: `patina-out/run-0/inc-0/stdout` and
`stderr`. Now run 20 seeds of the version with the bug:

```sh
patina sweep --seeds 1..20 -- target/debug/jobs
```

```text
patina sweep: 20 runs, 14 findings in 1 groups, 6 ok   (0.2s, 8 jobs)
outcomes: failure 14, ok 6

failure exit: panicked at src/main.rs:N:N: assertion `left == right` failed: results out of job order; exit 101
  seeds 14 of 20   first 1   replayed: identical
  rerun:  patina run --seed 1 -- /tmp/patina/examples/quickstart/target/debug/jobs
  replay: patina replay /tmp/patina/examples/quickstart/patina-out/sweep/seed-1
```

Each group is one bug: its signature, how many seeds hit it, and the first of them. Patina
already replayed that seed once and got the same run. The run directory holds the evidence:

```sh
cat patina-out/sweep/seed-1/inc-0/stderr
```

```text
thread 'main' (2) panicked at src/main.rs:28:5:
assertion `left == right` failed: results out of job order
  left: [2, 1, 3]
 right: [1, 2, 3]
```

`patina replay DIR` runs the seed again and compares every system call with the recorded one.
Fix the code, rebuild, and sweep into a new directory (a sweep keeps the runs it finds in its
`--out`, default `patina-out/sweep`).

## What works

Any Linux x86_64 executable: static or dynamic, Rust, C, C++, Go, Python, shell scripts and
the programs they start. Threads, `fork`, `exec`, pipes, files, timers, signals and TCP on
localhost all run, decided by the seed. The program sees a fixed machine: 4 CPUs, one clock
that starts at the same time every run, an empty writable `/work` as its working directory.

What it does not do: UDP and other non-TCP network sockets (the call fails with an error),
connections to anything outside the run, and macOS or arm64 hosts. A call Patina does not
model ends the run `unsupported` and names it. [ARCHITECTURE.md](ARCHITECTURE.md#limits)
lists the limits.

## Outcomes

Every run ends in one outcome; the exit status of `patina` follows from it.

| Outcome | Exit | Meaning |
|---|---|---|
| `ok` | 0 | the program exited 0 and broke no invariant |
| `violation` | 1 | an SDK invariant (`always`) failed |
| `liveness` | 1 | every thread blocked, or the virtual time limit passed |
| `failure` | 1 | the program exited nonzero |
| `crash` | 1 | the program died on a signal |
| `unsupported` | 2 | the program did something Patina does not model; the message names it |
| `timeout` | 2 | the wall-time limit passed |
| `nondeterministic` | 2 | a replay differed from its run: a Patina bug, please report it |
| `internal` | 2 | Patina failed, or the host refused a resource |
| `vacuous` | 2 | a sweep's fault or SDK check never had anything to act on |
| `error` | 2 | the command could not be carried out |

## Where next

- [examples/README.md](examples/README.md): one bug each found by scheduling, by an SDK fault
  point, by disk faults, by crashes and by network faults, in Rust, Python, C and Go.
- [docs/GUIDE.md](docs/GUIDE.md): sweeps, faults, crashes, the SDK, reading a result,
  replay, CI.
- [ARCHITECTURE.md](ARCHITECTURE.md): how it works and its limits.
- `patina --help`, `patina COMMAND --help`: every flag of your build.
